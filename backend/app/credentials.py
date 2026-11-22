"""Connector credential storage service (M04, issue #7).

Everything that touches plaintext lives here and in ``app.crypto``. The HTTP
layer only ever receives ``ConnectorCredential`` rows rendered through
``to_status`` (masked metadata). ``reveal`` is for future in-process
connectors and is deliberately not exposed over HTTP.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from . import crypto, models
from .credential_schemas import (
    CREDENTIAL_TYPES,
    MASK,
    CredentialStatus,
    CredentialTypeSpec,
    CredentialWrite,
)

CONNECTOR_NAME_PATTERN = r"^[a-z][a-z0-9_-]{0,62}$"
_CONNECTOR_RE = re.compile(CONNECTOR_NAME_PATTERN)


class CredentialValidationError(ValueError):
    """Carries sanitized (loc/msg/type only) validation details."""

    def __init__(self, errors: list[dict]):
        super().__init__("Invalid credential payload")
        self.errors = errors


@dataclass(frozen=True)
class Scope:
    kind: str  # "device" | "connector"
    ident: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.ident}"

    @classmethod
    def device(cls, device_id: str) -> Scope:
        return cls("device", device_id)

    @classmethod
    def connector(cls, name: str) -> Scope:
        if not _CONNECTOR_RE.match(name):
            raise ValueError("invalid connector name")
        return cls("connector", name)


def get_spec(credential_type: str) -> CredentialTypeSpec | None:
    return CREDENTIAL_TYPES.get(credential_type)


def _sanitize(exc: ValidationError, prefix: str) -> list[dict]:
    # Pydantic's ``input``/``ctx`` members can contain the submitted secret.
    return [
        {"loc": [prefix, *[str(p) for p in e["loc"]]], "msg": e["msg"], "type": e["type"]}
        for e in exc.errors(include_input=False, include_url=False, include_context=False)
    ]


def _validate(model: type[BaseModel], data: dict, prefix: str) -> BaseModel:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise CredentialValidationError(_sanitize(exc, prefix)) from None


def validate_write(spec: CredentialTypeSpec, body: CredentialWrite) -> tuple[dict, dict]:
    """Return ``(secret_fields, metadata)`` validated for ``spec``."""
    raw_secret = {k: v.get_secret_value() for k, v in body.secret.items()}
    secret = _validate(spec.secret_model, raw_secret, "secret")
    meta = _validate(spec.meta_model, body.metadata, "metadata")
    secret_fields = {
        name: value.get_secret_value() if hasattr(value, "get_secret_value") else value
        for name, value in secret
    }
    return secret_fields, meta.model_dump(exclude_none=True)


def _aad(row_id: str, scope_key: str, credential_type: str, version: int) -> bytes:
    return crypto.build_aad(
        credential_id=row_id,
        scope_key=scope_key,
        credential_type=credential_type,
        version=version,
    )


def find(db: Session, scope: Scope, credential_type: str) -> models.ConnectorCredential | None:
    return (
        db.query(models.ConnectorCredential)
        .filter(
            models.ConnectorCredential.scope_key == scope.key,
            models.ConnectorCredential.credential_type == credential_type,
        )
        .first()
    )


def upsert(
    db: Session,
    scope: Scope,
    spec: CredentialTypeSpec,
    secret_fields: dict,
    metadata: dict,
) -> tuple[models.ConnectorCredential, bool]:
    """Create or rotate a credential. Returns ``(row, created)``.

    Encryption happens before any row is touched, so a missing/invalid key
    raises ``CredentialKeyError`` with the database unchanged. Rotation
    overwrites the ciphertext in place (same row id, so the AAD stays
    stable); the previous ciphertext is not retained anywhere.
    """
    key = crypto.load_key()
    plaintext = json.dumps(secret_fields, separators=(",", ":"), sort_keys=True).encode("utf-8")
    now = datetime.now(UTC)
    row = find(db, scope, spec.name)
    created = row is None
    row_id = str(uuid.uuid4()) if row is None else row.id
    envelope = crypto.encrypt(
        plaintext,
        aad=_aad(row_id, scope.key, spec.name, crypto.FORMAT_VERSION),
        key=key,
    )
    if row is None:
        row = models.ConnectorCredential(
            id=row_id,
            scope_key=scope.key,
            device_id=scope.ident if scope.kind == "device" else None,
            connector=scope.ident if scope.kind == "connector" else None,
            credential_type=spec.name,
            created_at=now,
        )
        db.add(row)
    else:
        row.rotated_at = now
    row.enc_version = crypto.FORMAT_VERSION
    row.ciphertext = envelope
    row.meta = metadata
    row.updated_at = now
    return row, created


def delete(db: Session, scope: Scope, credential_type: str) -> bool:
    row = find(db, scope, credential_type)
    if row is None:
        return False
    db.delete(row)
    return True


def reveal(row: models.ConnectorCredential) -> dict:
    """Decrypt a stored credential for in-process connector use ONLY.

    Raises ``CredentialKeyError`` / ``CredentialDecryptionError``; callers
    must treat both as "credential unavailable" and never fall back.
    """
    plaintext = crypto.decrypt(
        row.ciphertext,
        aad=_aad(row.id, row.scope_key, row.credential_type, row.enc_version),
    )
    try:
        data = json.loads(plaintext)
    except ValueError:
        raise crypto.CredentialDecryptionError("Stored credential could not be decrypted") from None
    if not isinstance(data, dict):
        raise crypto.CredentialDecryptionError("Stored credential could not be decrypted")
    return data


def to_status(
    scope: Scope, credential_type: str, row: models.ConnectorCredential | None
) -> CredentialStatus:
    base = {
        "scope": scope.kind,
        "device_id": scope.ident if scope.kind == "device" else None,
        "connector": scope.ident if scope.kind == "connector" else None,
        "credential_type": credential_type,
    }
    if row is None:
        return CredentialStatus(configured=False, **base)
    return CredentialStatus(
        configured=True,
        masked=MASK,
        metadata=dict(row.meta or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
        rotated_at=row.rotated_at,
        **base,
    )
