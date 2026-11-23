# backend/app/models.py
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
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


class ConnectorCredential(Base):
    """Encrypted connector secret plus non-secret metadata (M04).

    Kept apart from ``Device`` and ``DeviceObservation`` so that credentials
    can never ride along in inventory reads or observation history. A row is
    scoped to exactly one canonical device *or* one named connector (e.g. a
    UniFi controller), and holds at most one credential per type per scope.
    ``ciphertext`` is a versioned AES-256-GCM envelope (see ``app.crypto``);
    the key is never stored in the database.
    """

    __tablename__ = "connector_credentials"
    __table_args__ = (
        UniqueConstraint("scope_key", "credential_type", name="uq_connector_credential_scope_type"),
        CheckConstraint(
            "((device_id IS NULL) + (connector IS NULL)) = 1",
            name="ck_connector_credential_one_scope",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # "device:<uuid>" or "connector:<name>"; unique-able even though one of
    # device_id/connector is always NULL.
    scope_key: Mapped[str] = mapped_column(String(128), nullable=False)
    device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=True
    )
    connector: Mapped[str | None] = mapped_column(String(64), nullable=True)
    credential_type: Mapped[str] = mapped_column(String(32), nullable=False)
    enc_version: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    meta: Mapped[dict] = mapped_column("meta", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    def __repr__(self) -> str:  # never render ciphertext
        return f"<ConnectorCredential id={self.id} type={self.credential_type}>"


class CredentialKeyVerifier(Base):
    """Versioned verifier binding the database to the credential master key.

    Singleton row (``id = 1``) holding a salted HMAC-SHA256 of a fixed,
    domain-separated message under the key (see ``app.key_binding``). It is
    one-way, never contains the key, and is kept apart from credential
    ciphertext so it survives deletion of every credential.
    """

    __tablename__ = "credential_key_verifier"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_credential_key_verifier_singleton"),
        CheckConstraint("length(salt) = 16", name="ck_credential_key_verifier_salt"),
        CheckConstraint("length(verifier) = 32", name="ck_credential_key_verifier_len"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    verifier: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    def __repr__(self) -> str:  # never render verifier material
        return f"<CredentialKeyVerifier version={self.version}>"


class ScanJob(Base):
    """A durable scan job (M09), leased by at most one worker at a time.

    ``targets`` holds the *resolved, scope-validated* CIDRs (``{"v": [...]}``);
    the worker re-validates them against the current scope before running.
    ``lease_owner``/``lease_expires_at`` implement SQLite-backed leasing, and
    ``runner_pid`` is the scanner's process-group id so a restarted worker can
    reap a leftover scanner. Holds no credentials.
    """

    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','cancelling','succeeded','failed','cancelled')",
            name="ck_scan_jobs_status",
        ),
        Index("ix_scan_jobs_status_available_at", "status", "available_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="scan")
    profile: Mapped[str] = mapped_column(String(16), nullable=False)
    targets: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    available_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    runner_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Progress is measured in addresses covered, so it aggregates across chunks.
    progress_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class JobEvent(Base):
    """Append-only event log for a job; ``id`` is the polling cursor."""

    __tablename__ = "job_events"
    __table_args__ = (
        Index("ix_job_events_job_id_id", "job_id", "id"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    level: Mapped[str] = mapped_column(String(8), nullable=False, default="info")
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(String(512), nullable=False)
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)


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
