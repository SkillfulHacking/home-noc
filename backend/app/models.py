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
    false,
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


class ScanPolicy(Base):
    """Runtime scan policy (M08A, issue #66): exactly one row, ``id = 1``.

    Holds operational authorization only -- never secrets. CIDR lists are
    stored normalized as ``{"v": [...]}``. ``revision`` is the optimistic
    concurrency token and the signal workers use to notice a change. The
    environment (``SCAN_ALLOWED_CIDRS`` / ``SCAN_ALLOW_PUBLIC``) stays an
    immutable ceiling on top of whatever is stored here.
    """

    __tablename__ = "scan_policy"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_scan_policy_singleton"),
        CheckConstraint("revision >= 1", name="ck_scan_policy_revision"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    private_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    private_allowlist: Mapped[dict] = mapped_column(JSON, nullable=False)
    # Strict mode: only ``private_allowlist`` ranges are authorized (an empty
    # list authorizes nothing). Off: all RFC1918, subject to ceilings/exclusions.
    private_strict: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    public_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    public_allowlist: Mapped[dict] = mapped_column(JSON, nullable=False)
    exclusions: Mapped[dict] = mapped_column(JSON, nullable=False)
    # fresh | upgrade | upgrade_env_scope | dev_default -- how this row was seeded.
    bootstrap_origin: Mapped[str] = mapped_column(String(24), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False)


class ScanPolicyAudit(Base):
    """Append-only audit of scan policy changes and rejected attempts."""

    __tablename__ = "scan_policy_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    outcome: Mapped[str] = mapped_column(String(48), nullable=False)
    prior_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    new_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prior: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new: Mapped[dict | None] = mapped_column(JSON, nullable=True)


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


class ConnectorSetting(Base):
    """Non-secret settings and health state of a named connector (M14).

    Credentials stay in ``connector_credentials``. ``enabled`` defaults to
    false: a connector never contacts anything until an administrator turns it
    on (sync and polling refuse while disabled; the explicit admin ``/test`` action may
    run before enabling), and failures never disable or delete stored credentials.
    """

    __tablename__ = "connector_settings"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    base_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    site: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class Schedule(Base):
    """A recurring job definition (M16). All times are UTC.

    ``next_run_at`` is advanced with a compare-and-set in the same transaction
    that enqueues the job, so restarts and multiple schedulers cannot duplicate
    a run. Scan targets are re-authorized against the live policy at every
    firing; the schedule itself carries no credentials.
    """

    __tablename__ = "schedules"
    __table_args__ = (
        CheckConstraint("kind IN ('scan','snmp_poll','unifi_sync')", name="ck_schedules_kind"),
        Index("ix_schedules_enabled_next_run", "enabled", "next_run_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    profile: Mapped[str | None] = mapped_column(String(16), nullable=True)
    targets: Mapped[dict] = mapped_column(JSON, nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    jitter_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    next_run_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class DeviceHealth(Base):
    """Current derived health of one device (M19). ``sources`` holds per-source
    evidence ({source: {last_success, last_attempt, failures}}); the status and
    reason are derived by ``app.health.evaluate`` and never set by hand."""

    __tablename__ = "device_health"

    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    reason: Mapped[str] = mapped_column(String(160), nullable=False, default="never observed")
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    status_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    sources: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class HealthSnapshot(Base):
    """Lightweight status time series: written on every transition plus an hourly
    heartbeat, and pruned to a fixed number of rows per device."""

    __tablename__ = "health_snapshots"
    __table_args__ = (Index("ix_health_snapshots_device_at", "device_id", "at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(160), nullable=False)


class Event(Base):
    """A deduplicated operational event (M20). ``dedupe_key`` + ``cooldown`` collapse
    repeats into ``count``/``last_at`` instead of new rows. Holds no credentials."""

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_at", "at", "id"),
        Index("ix_events_device_at", "device_id", "at"),
        Index("ix_events_dedupe", "dedupe_key", "last_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    summary: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    dedupe_key: Mapped[str] = mapped_column(String(160), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Finding(Base):
    """A deduplicated vulnerability finding on one asset/service (M18).

    ``fingerprint`` identifies the same issue across reruns, so repeats update this
    row. Only sanitized, redacted, size-bounded fields are stored (no raw
    request/response or credentials)."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("device_id", "fingerprint", name="uq_finding_device_fingerprint"),
        Index("ix_findings_status_severity", "status", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    template_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="open")
    host: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    scheme: Mapped[str] = mapped_column(String(8), nullable=False)
    path: Mapped[str] = mapped_column(String(200), nullable=False, default="/")
    matcher_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    suppressed_reason: Mapped[str | None] = mapped_column(String(300), nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    template_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    scanner_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class FindingEvent(Base):
    """Append-only lifecycle/audit trail of a finding (opened, seen, resolved, ...)."""

    __tablename__ = "finding_events"
    __table_args__ = (Index("ix_finding_events_finding_at", "finding_id", "at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    note: Mapped[str | None] = mapped_column(String(300), nullable=True)
