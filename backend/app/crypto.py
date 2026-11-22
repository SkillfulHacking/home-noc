"""Authenticated encryption for connector credentials (M04, issue #7).

Envelope layout (all bytes)::

    +---------+-----------+----------------------------+
    | version | nonce(12) | AES-256-GCM ciphertext+tag |
    +---------+-----------+----------------------------+

* AES-256-GCM, a fresh 96-bit random nonce per encryption.
* The key comes from configuration only. It is never generated here, never
  written anywhere, and there is no plaintext fallback: every failure path
  raises instead of returning or storing unencrypted data.
* The caller supplies associated data (see ``build_aad``) that binds a
  ciphertext to its credential identity. Moving a ciphertext to another
  row, scope or type makes the GCM tag check fail.
* The format version is both in the envelope header and in the AAD, so a
  future algorithm/key rotation scheme can be introduced without ambiguity
  and a header edit is detected as tampering.
* Exception text never includes key material, plaintext or ciphertext.
"""
from __future__ import annotations

import base64
import binascii
import logging
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
SUPPORTED_VERSIONS = frozenset({FORMAT_VERSION})
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
_HEADER_BYTES = 1
MIN_ENVELOPE_BYTES = _HEADER_BYTES + NONCE_BYTES + TAG_BYTES


class CredentialCryptoError(Exception):
    """Base class; messages are deliberately generic and secret-free."""


class CredentialKeyError(CredentialCryptoError):
    """The encryption key is missing or unusable. Callers must fail closed."""


class CredentialDecryptionError(CredentialCryptoError):
    """Ciphertext is malformed, tampered with, bound elsewhere, or the key is wrong."""


def _decode_key(raw: str) -> bytes:
    candidate = raw.strip()
    if not candidate:
        raise CredentialKeyError("Credential encryption key is empty")
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        # validate=True rejects stray characters instead of silently skipping them.
        key = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise CredentialKeyError(
            "Credential encryption key must be urlsafe-base64 encoded"
        ) from None
    if len(key) != KEY_BYTES:
        raise CredentialKeyError(
            f"Credential encryption key must decode to exactly {KEY_BYTES} bytes"
        )
    if key == bytes(KEY_BYTES):
        raise CredentialKeyError("Credential encryption key must not be all zero bytes")
    return key


def load_key() -> bytes:
    """Return the configured 32-byte key or raise ``CredentialKeyError``."""
    inline = settings.credential_encryption_key
    key_file = settings.credential_encryption_key_file
    inline_value = inline.get_secret_value() if inline is not None else None

    if inline_value and key_file:
        raise CredentialKeyError(
            "Set only one of CREDENTIAL_ENCRYPTION_KEY and CREDENTIAL_ENCRYPTION_KEY_FILE"
        )
    if inline_value:
        return _decode_key(inline_value)
    if key_file:
        try:
            raw = Path(key_file).read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError):
            raise CredentialKeyError("Credential encryption key file is not readable") from None
        return _decode_key(raw)
    raise CredentialKeyError("Credential encryption key is not configured")


def build_aad(
    *, credential_id: str, scope_key: str, credential_type: str, version: int = FORMAT_VERSION
) -> bytes:
    """Associated data binding a ciphertext to its credential identity."""
    return "\x00".join(
        ("home-noc/credential", f"v{version}", credential_id, scope_key, credential_type)
    ).encode("utf-8")


def encrypt(plaintext: bytes, *, aad: bytes, key: bytes | None = None) -> bytes:
    """Encrypt ``plaintext`` and return a versioned envelope."""
    resolved = key if key is not None else load_key()
    if len(resolved) != KEY_BYTES:
        raise CredentialKeyError("Credential encryption key has the wrong length")
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(resolved).encrypt(nonce, plaintext, aad)
    return bytes([FORMAT_VERSION]) + nonce + sealed


def envelope_version(envelope: bytes) -> int:
    if not envelope:
        raise CredentialDecryptionError("Stored credential could not be decrypted")
    return envelope[0]


def decrypt(envelope: bytes, *, aad: bytes, key: bytes | None = None) -> bytes:
    """Verify and decrypt an envelope; raise ``CredentialDecryptionError`` on any defect."""
    resolved = key if key is not None else load_key()
    if len(resolved) != KEY_BYTES:
        raise CredentialKeyError("Credential encryption key has the wrong length")
    generic = CredentialDecryptionError("Stored credential could not be decrypted")
    if not isinstance(envelope, bytes | bytearray | memoryview):
        raise generic
    data = bytes(envelope)
    if len(data) < MIN_ENVELOPE_BYTES or data[0] not in SUPPORTED_VERSIONS:
        raise generic
    nonce = data[_HEADER_BYTES : _HEADER_BYTES + NONCE_BYTES]
    sealed = data[_HEADER_BYTES + NONCE_BYTES :]
    try:
        return AESGCM(resolved).decrypt(nonce, sealed, aad)
    except InvalidTag:
        raise generic from None


def validate_credential_key_configuration() -> None:
    """Startup check.

    A key that is *present but unusable* is a deployment error and stops a
    production start. A *missing* key does not stop the app (inventory and
    auth do not need it) but every credential operation then fails closed
    with a 503 until the operator provisions one.
    """
    try:
        load_key()
    except CredentialKeyError as exc:
        configured = bool(
            settings.credential_encryption_key or settings.credential_encryption_key_file
        )
        if configured and settings.is_production:
            raise
        logger.warning(
            "Connector credential storage is DISABLED: %s. Credential endpoints will "
            "return 503 until a valid key is provisioned.",
            exc,
        )
