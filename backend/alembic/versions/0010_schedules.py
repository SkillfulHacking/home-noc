"""recurring schedules (M16, issue #19)

Revision ID: 0010_schedules
Revises: 0009_connector_settings
Create Date: 2026-11-26 15:00:00

Adds ``schedules``. Downgrade drops only that table; jobs already queued stay.
"""
import sqlalchemy as sa

from alembic import op

revision = "0010_schedules"
down_revision = "0009_connector_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "schedules" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("profile", sa.String(16), nullable=True),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("jitter_percent", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_job_id", sa.String(36), nullable=True),
        sa.Column("last_error_code", sa.String(32), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('scan','snmp_poll','unifi_sync')", name="ck_schedules_kind"),
    )
    op.create_index("ix_schedules_enabled_next_run", "schedules", ["enabled", "next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_schedules_enabled_next_run", table_name="schedules")
    op.drop_table("schedules")
