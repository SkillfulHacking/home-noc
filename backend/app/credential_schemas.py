"""Credential type registry and API shapes (M04, issue #7).

Adding a connector credential type means adding one ``CredentialTypeSpec``
to ``CREDENTIAL_TYPES``: which scopes it may attach to, the model that
validates its secret fields, and the model that validates its non-secret
metadata. Nothing else in the storage or API layers changes.

Validators here must never echo the submitted value in an error message.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

MASK = "********"  # fixed-width: reveals neither content nor length

ScopeKind = Literal["device", "connector"]


def _no_control_chars(v: SecretStr) -> SecretStr:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in v.get_secret_value()):
        raise ValueError("must not contain control characters")
    return v


class _Secret(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UniFiTokenSecret(_Secret):
    token: SecretStr = Field(min_length=8, max_length=4096)

    _check = field_validator("token")(_no_control_chars)


class SNMPv3Secret(_Secret):
    # RFC 3414 requires at least 8 characters for USM passphrases.
    password: SecretStr = Field(min_length=8, max_length=1024)

    _check = field_validator("password")(_no_control_chars)


class _Meta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, max_length=64, pattern=r"^[\w .:@/-]*$")


class UniFiTokenMeta(_Meta):
    pass


class SNMPv3AuthMeta(_Meta):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[\w.@-]+$")
    protocol: Literal["SHA", "SHA224", "SHA256", "SHA384", "SHA512"] = "SHA256"


class SNMPv3PrivMeta(_Meta):
    protocol: Literal["AES128", "AES192", "AES256"] = "AES128"


@dataclass(frozen=True)
class CredentialTypeSpec:
    name: str
    scopes: frozenset[str]
    secret_model: type[BaseModel]
    meta_model: type[BaseModel]


CREDENTIAL_TYPES: dict[str, CredentialTypeSpec] = {
    spec.name: spec
    for spec in (
        CredentialTypeSpec(
            "unifi_api_token",
            frozenset({"connector", "device"}),
            UniFiTokenSecret,
            UniFiTokenMeta,
        ),
        CredentialTypeSpec(
            "snmpv3_auth", frozenset({"device"}), SNMPv3Secret, SNMPv3AuthMeta
        ),
        CredentialTypeSpec(
            "snmpv3_priv", frozenset({"device"}), SNMPv3Secret, SNMPv3PrivMeta
        ),
    )
}


class CredentialWrite(BaseModel):
    """Body of a create/rotate request. Secret values stay inside ``SecretStr``
    so accidental ``repr``/logging of the model cannot reveal them."""

    model_config = ConfigDict(extra="forbid")

    secret: dict[str, SecretStr] = Field(min_length=1, max_length=8)
    metadata: dict[str, Any] = Field(default_factory=dict, max_length=16)


class CredentialStatus(BaseModel):
    """Masked view. There is intentionally no field that can carry a secret
    value or ciphertext."""

    model_config = ConfigDict(extra="forbid")

    scope: ScopeKind
    device_id: str | None = None
    connector: str | None = None
    credential_type: str
    configured: bool
    masked: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    rotated_at: datetime | None = None


class CredentialList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credentials: list[CredentialStatus]
