"""Binding of the credential master key to the database (M04).

A single row in ``credential_key_verifier`` holds::

    verifier = HMAC-SHA256(master_key,
                           "home-noc/credential-key-verifier" 0x00 "v<version>" 0x00 salt)

The domain-separated, per-database-salted MAC is one-way: it does not reveal
or help recover the key, and it is not reusable as an AES key or as any other
MAC. The raw key is never stored, logged or returned, and error messages are
fixed strings.

Rules enforced here:

* The verifier is created once and never updated or replaced. A different key
  is rejected, including after every credential row was deleted.
* A database holding credentials but no verifier (created before this
  migration) is only bound after *every* stored ciphertext authenticates with
  the supplied key. Otherwise nothing is written.
* On a database without credentials the verifier is created in the same
  transaction as the first credential write. The singleton primary key makes
  concurrent first writers race on one INSERT; the loser re-reads the winner's
  verifier and is rejected if its key differs.

This is detection of a wrong key, not key rotation.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from . import crypto, models
from .config import settings
from .db import SessionLocal

logger = logging.getLogger(__name__)

VERIFIER_VERSION = 1
SUPPORTED_VERIFIER_VERSIONS = frozenset({VERIFIER_VERSION})
SALT_BYTES = 16
_DOMAIN = b"home-noc/credential-key-verifier"
_ROW_ID = 1


class CredentialKeyMismatchError(crypto.CredentialCryptoError):
    """The configured key does not belong to this database."""


class CredentialKeyVerificationUnavailable(crypto.CredentialCryptoError):
    """Key/database compatibility could not be established; fail closed."""


def _mismatch() -> CredentialKeyMismatchError:
    return CredentialKeyMismatchError(
        "Configured credential key does not match this database"
    )


def _unavailable() -> CredentialKeyVerificationUnavailable:
    return CredentialKeyVerificationUnavailable("Credential key verification is unavailable")


def compute_verifier(key: bytes, *, version: int, salt: bytes) -> bytes:
    if len(key) != crypto.KEY_BYTES:
        raise crypto.CredentialKeyError("Credential encryption key has the wrong length")
    message = b"\x00".join((_DOMAIN, f"v{version}".encode("ascii"), salt))
    return hmac.new(key, message, hashlib.sha256).digest()


def _get_record(db: Session) -> models.CredentialKeyVerifier | None:
    return db.execute(
        select(models.CredentialKeyVerifier)
        .where(models.CredentialKeyVerifier.id == _ROW_ID)
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()


def _verify_record(record: models.CredentialKeyVerifier, key: bytes) -> None:
    if record.version not in SUPPORTED_VERIFIER_VERSIONS:
        raise _unavailable()
    expected = compute_verifier(key, version=record.version, salt=bytes(record.salt))
    if not hmac.compare_digest(expected, bytes(record.verifier)):
        raise _mismatch()


def _authenticate_existing(db: Session, key: bytes) -> None:
    """Every stored credential must decrypt under ``key`` (pre-verifier databases)."""
    for row in db.query(models.ConnectorCredential).all():
        aad = crypto.build_aad(
            credential_id=row.id,
            scope_key=row.scope_key,
            credential_type=row.credential_type,
            version=row.enc_version,
        )
        try:
            crypto.decrypt(row.ciphertext, aad=aad, key=key)
        except crypto.CredentialDecryptionError:
            raise _mismatch() from None


def authenticate_existing(db: Session, key: bytes) -> None:
    """Read-only: raise unless every stored ciphertext authenticates under ``key``.

    Used by restore for backups that predate the verifier table (migration
    0005): there is no verifier to compare, so the only proof that ``key``
    belongs to the data is that the existing ciphertext decrypts with it.
    """
    try:
        _authenticate_existing(db, key)
    except OperationalError:
        raise _unavailable() from None


def check_usable(db: Session, key: bytes | None = None) -> None:
    """Read-only: raise unless the configured key is valid for this database."""
    resolved = key if key is not None else crypto.load_key()
    try:
        record = _get_record(db)
        if record is not None:
            _verify_record(record, resolved)
        else:
            _authenticate_existing(db, resolved)
    except OperationalError:
        raise _unavailable() from None


def bind_for_write(db: Session, key: bytes) -> None:
    """Call before encrypting a new/rotated credential in this transaction.

    May add the verifier row to the session; it commits atomically with the
    credential write. Raises a ``CredentialCryptoError`` subclass on any
    doubt, in which case the caller must roll back and write nothing.
    """
    try:
        record = _get_record(db)
        if record is not None:
            _verify_record(record, key)
            return
        _authenticate_existing(db, key)
        salt = os.urandom(SALT_BYTES)
        db.add(
            models.CredentialKeyVerifier(
                id=_ROW_ID,
                version=VERIFIER_VERSION,
                salt=salt,
                verifier=compute_verifier(key, version=VERIFIER_VERSION, salt=salt),
                created_at=datetime.now(UTC),
            )
        )
        db.flush()
    except IntegrityError:
        # Another writer created the verifier first. Never overwrite it:
        # re-read the committed one and require our key to match.
        db.rollback()
        try:
            winner = _get_record(db)
        except OperationalError:
            raise _unavailable() from None
        if winner is None:
            raise _unavailable() from None
        _verify_record(winner, key)
    except OperationalError:
        db.rollback()
        raise _unavailable() from None


def verify_at_startup() -> None:
    """Detect a wrong key on restart. Fatal in production, logged otherwise."""
    try:
        key = crypto.load_key()
    except crypto.CredentialKeyError:
        return  # missing/invalid key is handled by validate_credential_key_configuration
    with SessionLocal() as db:
        try:
            check_usable(db, key)
        except CredentialKeyMismatchError:
            logger.error(
                "Configured credential encryption key does not match this database; "
                "credential operations are disabled. Supply the original key."
            )
            if settings.is_production:
                raise
        except CredentialKeyVerificationUnavailable:
            logger.warning(
                "Credential key verification skipped: schema not migrated yet "
                "(credential operations stay unavailable until it is)."
            )
