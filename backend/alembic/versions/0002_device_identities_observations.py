"""device identities and observations; scrub legacy snmp secrets

Revision ID: 0002_device_identities_observations
Revises: 0001_init_devices
Create Date: 2026-11-22 00:00:00
"""
import json
import re
import uuid
from datetime import datetime, UTC

import sqlalchemy as sa

from alembic import op

# Mirrors app.validators.normalize_mac's accepted formats. Duplicated here
# (rather than imported) so this migration's behavior stays fixed even if
# the application-level validator changes later.
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2})([:-]?)(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}$")

revision = "0002_device_identities_observations"
down_revision = "0001_init_devices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "device_identities" not in tables:
        op.create_table(
            "device_identities",
            sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
            sa.Column(
                "device_id",
                sa.String(length=36),
                sa.ForeignKey("devices.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("source", sa.String(length=64), nullable=False),
            sa.Column("external_id", sa.String(length=255), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "source", "external_id", name="uq_device_identity_source_external_id"
            ),
        )
        op.create_index(
            "ix_device_identities_device_id", "device_identities", ["device_id"]
        )

    if "device_observations" not in tables:
        op.create_table(
            "device_observations",
            sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
            sa.Column(
                "device_id",
                sa.String(length=36),
                sa.ForeignKey("devices.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("source", sa.String(length=32), nullable=False),
            sa.Column("source_ref", sa.String(length=255), nullable=True),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("data", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_device_observations_device_id", "device_observations", ["device_id"]
        )

    tables = set(sa.inspect(bind).get_table_names())
    _backfill_mac_identities(bind, tables)
    _scrub_legacy_snmp_secrets(bind, tables)


def _normalize_mac(value: str) -> str | None:
    v = value.strip()
    if not _MAC_RE.match(v):
        return None
    hex_digits = re.sub(r"[:-]", "", v).lower()
    return ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2))


def _backfill_mac_identities(bind, tables: set[str]) -> None:
    """Devices created before this migration may already carry a `mac` value
    that was never uniqueness-enforced. Backfill one `device_identities` row
    per device so the new unique constraint applies going forward.

    Pre-existing legacy data may contain two devices that already share a
    (possibly differently-formatted) MAC. We must never merge those into one
    device here -- that would silently destroy an operator's asset history.
    Instead, the first device (by id order) claims the normalized MAC's
    identity row and the rest are left without one for an operator to
    resolve manually; unparsable/malformed legacy mac values are skipped
    entirely rather than aborting the migration.
    """
    if "devices" not in tables or "device_identities" not in tables:
        return

    devices = sa.table("devices", sa.column("id", sa.String), sa.column("mac", sa.String))
    identities = sa.table(
        "device_identities",
        sa.column("id", sa.String),
        sa.column("device_id", sa.String),
        sa.column("source", sa.String),
        sa.column("external_id", sa.String),
        sa.column("created_at", sa.DateTime),
    )

    existing = bind.execute(
        sa.select(identities.c.device_id, identities.c.external_id).where(
            identities.c.source == "mac"
        )
    ).fetchall()
    claimed_macs = {external_id for _, external_id in existing}
    devices_with_identity = {device_id for device_id, _ in existing}

    rows = bind.execute(
        sa.select(devices.c.id, devices.c.mac).order_by(devices.c.id)
    ).fetchall()
    now = datetime.now(UTC)
    for device_id, mac in rows:
        if not mac:
            continue
        normalized = _normalize_mac(mac)
        if normalized is None:
            continue
        # Store the canonical form on the legacy device row as well as in
        # the identity table. Otherwise an unrelated PATCH can copy the old
        # dash/uppercase form back into the identity and bypass uniqueness.
        if mac != normalized:
            bind.execute(
                devices.update().where(devices.c.id == device_id).values(mac=normalized)
            )
        if device_id in devices_with_identity or normalized in claimed_macs:
            continue
        claimed_macs.add(normalized)
        bind.execute(
            identities.insert().values(
                id=str(uuid.uuid4()),
                device_id=device_id,
                source="mac",
                external_id=normalized,
                created_at=now,
            )
        )


def _scrub_legacy_snmp_secrets(bind, tables: set[str]) -> None:
    """Earlier versions of the SNMPInfo schema allowed a `community_or_user`
    credential field to be stored on the device's snmp JSON column. The
    canonical asset model must never hold credentials, so strip it from any
    existing rows."""
    if "devices" not in tables:
        return

    devices = sa.table(
        "devices",
        sa.column("id", sa.String),
        sa.column("snmp", sa.JSON),
    )
    rows = bind.execute(sa.select(devices.c.id, devices.c.snmp)).fetchall()
    for row_id, snmp in rows:
        if isinstance(snmp, str):
            try:
                snmp = json.loads(snmp)
            except (TypeError, ValueError):
                continue
        if isinstance(snmp, dict) and "community_or_user" in snmp:
            cleaned = {k: v for k, v in snmp.items() if k != "community_or_user"}
            bind.execute(
                devices.update().where(devices.c.id == row_id).values(snmp=cleaned)
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "device_observations" in tables:
        try:
            existing_indexes = [
                ix["name"] for ix in inspector.get_indexes("device_observations")
            ]
        except Exception:
            existing_indexes = []
        if "ix_device_observations_device_id" in existing_indexes:
            op.drop_index(
                "ix_device_observations_device_id", table_name="device_observations"
            )
        op.drop_table("device_observations")

    if "device_identities" in tables:
        try:
            existing_indexes = [
                ix["name"] for ix in inspector.get_indexes("device_identities")
            ]
        except Exception:
            existing_indexes = []
        if "ix_device_identities_device_id" in existing_indexes:
            op.drop_index(
                "ix_device_identities_device_id", table_name="device_identities"
            )
        op.drop_table("device_identities")
