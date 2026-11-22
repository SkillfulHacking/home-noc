# backend/app/schemas.py
from __future__ import annotations

from datetime import datetime
from typing import Literal
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .validators import ensure_utc, normalize_hardware_text, normalize_ip, normalize_mac

DiscoveryMethod = Literal["scan", "snmp", "api", "manual"]

# Observation/identity payloads must never carry credential material; the
# canonical asset model and its history are not a secrets store.
_FORBIDDEN_DATA_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "community",
    "community_or_user",
    "credential",
    "credentials",
    "private_key",
    "access_token",
    "refresh_token",
    "auth_token",
    "client_secret",
    "auth_password",
    "privacy_password",
    "passphrase",
}


def _find_forbidden_key(value: object) -> str | None:
    """Recursively search dicts/lists for a credential-shaped key at any depth
    so secrets can't be smuggled into observation data inside a nested object
    (e.g. ``{"snmp": {"community_or_user": "..."}}``)."""
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized_key = str(key).strip().lower().replace("-", "_")
            if normalized_key in _FORBIDDEN_DATA_KEYS:
                return str(key)
            found = _find_forbidden_key(nested)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_forbidden_key(item)
            if found is not None:
                return found
    return None


class Port(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"]
    service: str | None = None
    state: Literal["open", "closed", "filtered"] | None = None


class SNMPInfo(BaseModel):
    """Non-secret SNMP status only. Community strings/credentials belong to a
    dedicated connector credential store, never to the canonical asset model.

    ``extra="forbid"`` so legacy/unexpected fields (e.g. the old
    ``community_or_user`` credential field) are rejected with a 422 instead
    of being silently dropped by Pydantic's default extra-field handling.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    version: Literal["v2c", "v3"] | None = None


class APIInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["rest", "ssh", "netconf", "vendor"] | None = None
    url: str | None = None

    @field_validator("url")
    @classmethod
    def _reject_embedded_credentials(cls, v: str | None) -> str | None:
        if v is None:
            return v
        parts = urlsplit(v)
        if parts.username or parts.password:
            raise ValueError("url must not embed credentials (user:pass@host)")
        forbidden_query_key = next(
            (
                key
                for key, _ in parse_qsl(parts.query)
                if key.strip().lower().replace("-", "_") in _FORBIDDEN_DATA_KEYS
            ),
            None,
        )
        if forbidden_query_key is not None:
            raise ValueError(f"url must not embed credential query field {forbidden_query_key!r}")
        return v


Role = Literal["switch", "router", "ap", "server", "camera", "iot", "nas", "printer"]


class _DeviceFieldValidators(BaseModel):
    """Shared IP/MAC/timezone normalization for create, update and read shapes."""

    model_config = ConfigDict(extra="forbid")

    @field_validator("ip", mode="after", check_fields=False)
    @classmethod
    def _validate_ip(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return [normalize_ip(x) for x in v]

    @field_validator("mac", mode="after", check_fields=False)
    @classmethod
    def _validate_mac(cls, v: str | None) -> str | None:
        return normalize_mac(v) if v else v

    @field_validator("first_seen", "last_seen", mode="after", check_fields=False)
    @classmethod
    def _validate_tz(cls, v: datetime | None) -> datetime | None:
        return ensure_utc(v) if v is not None else v

    @field_validator("vendor", "model", "os", "serial", mode="before", check_fields=False)
    @classmethod
    def _normalize_hardware_text(cls, v: object) -> object:
        return normalize_hardware_text(v) if isinstance(v, str) or v is None else v


class DeviceBase(_DeviceFieldValidators):
    hostname: str
    ip: list[str] = Field(default_factory=list)
    mac: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    discovery_method: DiscoveryMethod | None = None
    vendor: str | None = None
    model: str | None = None
    os: str | None = None
    serial: str | None = None
    location: str | None = None
    roles: list[Role] = Field(default_factory=list)
    ports: list[Port] = Field(default_factory=list)
    snmp: SNMPInfo | None = None
    api: APIInfo | None = None
    notes: str | None = None


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(_DeviceFieldValidators):
    hostname: str | None = None
    ip: list[str] | None = None
    mac: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    discovery_method: DiscoveryMethod | None = None
    vendor: str | None = None
    model: str | None = None
    os: str | None = None
    serial: str | None = None
    location: str | None = None
    roles: list[Role] | None = None
    ports: list[Port] | None = None
    snmp: SNMPInfo | None = None
    api: APIInfo | None = None
    notes: str | None = None


class DeviceRead(DeviceBase):
    model_config = ConfigDict(from_attributes=True)

    id: str


class DeviceIdentityCreate(BaseModel):
    """A source-specific unique key (e.g. mac, serial, connector:<name>) for
    de-duplicating devices discovered repeatedly by the same source."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=64)
    external_id: str = Field(min_length=1, max_length=255)

    @field_validator("source")
    @classmethod
    def _normalize_source(cls, v: str) -> str:
        # Lowercased so e.g. "MAC" and "mac" can't bypass the
        # (source, external_id) uniqueness constraint as distinct sources.
        v = v.strip().lower()
        if not v:
            raise ValueError("must not be blank")
        if v in {"ip", "ipv4", "ipv6", "hostname"}:
            raise ValueError("mutable IP addresses and hostnames are not stable device identities")
        return v

    @field_validator("external_id")
    @classmethod
    def _strip_external_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v

    @field_validator("external_id")
    @classmethod
    def _normalize_mac_identity(cls, v: str, info) -> str:
        source = info.data.get("source")
        if source == "mac":
            return normalize_mac(v)
        return v


class DeviceIdentityRead(DeviceIdentityCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    device_id: str
    created_at: datetime


class DeviceObservationCreate(BaseModel):
    """A raw, timestamped sighting of a device from a single source.

    ``data`` holds whatever non-secret fields that source observed (hostname,
    ip, vendor, ports, etc.); it is history, not the curated asset record.
    """

    model_config = ConfigDict(extra="forbid")

    source: DiscoveryMethod
    source_ref: str | None = Field(default=None, max_length=255)
    observed_at: datetime | None = None
    data: dict = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def _tz(cls, v: datetime | None) -> datetime | None:
        return ensure_utc(v) if v is not None else v

    @field_validator("data")
    @classmethod
    def _no_secrets(cls, v: dict) -> dict:
        bad_key = _find_forbidden_key(v)
        if bad_key is not None:
            raise ValueError(f"observation data must not include credential field {bad_key!r}")
        return v


class DeviceObservationRead(DeviceObservationCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    device_id: str
    observed_at: datetime
    created_at: datetime


def new_id() -> str:
    return str(uuid4())
