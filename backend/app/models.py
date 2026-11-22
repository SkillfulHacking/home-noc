# backend/app/models.py
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from .db import Base


class UTCDateTime(TypeDecorator):
    """DateTime that always round-trips as timezone-aware UTC.

    SQLite silently drops tzinfo on read even when the column declares
    ``timezone=True``, so naive values coming back from storage are
    re-attached to UTC instead of being treated as local/ambiguous.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # store list under {"v": [...]}
    mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    discovery_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os: Mapped[str | None] = mapped_column(String(255), nullable=True)
    serial: Mapped[str | None] = mapped_column(String(255), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    roles: Mapped[dict | None] = mapped_column(JSON, nullable=True)   # {"v":[...]}
    ports: Mapped[dict | None] = mapped_column(JSON, nullable=True)   # {"v":[{...}]}
    snmp: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    api: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    notes: Mapped[str | None] = mapped_column(String(4096), nullable=True)


class DeviceObservation(Base):
    """A single raw sighting of a device by a scanner/connector/operator.

    Kept separate from the curated ``Device`` fields so the canonical asset
    record always reflects the operator-reviewed truth while still retaining
    the history of what each source reported. Must never contain credentials
    (enforced by ``schemas.DeviceObservationCreate``).
    """

    __tablename__ = "device_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=lambda: datetime.now(UTC)
    )


class DeviceIdentity(Base):
    """A source-provided unique identifier that maps to exactly one device.

    Enforces de-duplication: a given source's identity (e.g. a MAC address,
    a serial number, or a connector's external device ID) can only ever
    point at one canonical device row.
    """

    __tablename__ = "device_identities"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_device_identity_source_external_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=lambda: datetime.now(UTC)
    )


class AdminSession(Base):
    """A server-side administrator session (M03).

    Only digests of the session and CSRF tokens are stored, so a database
    read cannot be replayed as a live session. Rows are deleted on logout
    and on expiry, which is what makes revocation real rather than advisory.
    """

    __tablename__ = "admin_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
