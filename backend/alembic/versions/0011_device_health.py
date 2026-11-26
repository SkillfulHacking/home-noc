"""device health state and snapshots (M19, issue #22)

Revision ID: 0011_device_health
Revises: 0010_schedules
Create Date: 2026-11-26 17:00:00

Adds ``device_health`` and ``health_snapshots``. Downgrade drops only those tables.
"""
import sqlalchemy as sa

from alembic import op

revision = "0011_device_health"
down_revision = "0010_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "device_health" not in tables:
        op.create_table(
            "device_health",
            sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"),
                      primary_key=True),
            sa.Column("status", sa.String(16), nullable=False, server_default="unknown"),
            sa.Column("reason", sa.String(160), nullable=False, server_default="never observed"),
            sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("sources", sa.JSON(), nullable=False),
        )
    if "health_snapshots" not in tables:
        op.create_table(
            "health_snapshots",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("reason", sa.String(160), nullable=False),
        )
        op.create_index("ix_health_snapshots_device_at", "health_snapshots", ["device_id", "at"])


def downgrade() -> None:
    op.drop_index("ix_health_snapshots_device_at", table_name="health_snapshots")
    op.drop_table("health_snapshots")
    op.drop_table("device_health")
