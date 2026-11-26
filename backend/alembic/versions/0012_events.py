"""operational events (M20, issue #23)

Revision ID: 0012_events
Revises: 0011_device_health
Create Date: 2026-11-26 19:00:00

Adds ``events``. Downgrade drops only that table.
"""
import sqlalchemy as sa

from alembic import op

revision = "0012_events"
down_revision = "0011_device_health"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "events" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("summary", sa.String(255), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("dedupe_key", sa.String(160), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_events_at", "events", ["at", "id"])
    op.create_index("ix_events_device_at", "events", ["device_id", "at"])
    op.create_index("ix_events_dedupe", "events", ["dedupe_key", "last_at"])


def downgrade() -> None:
    op.drop_index("ix_events_dedupe", table_name="events")
    op.drop_index("ix_events_device_at", table_name="events")
    op.drop_index("ix_events_at", table_name="events")
    op.drop_table("events")
