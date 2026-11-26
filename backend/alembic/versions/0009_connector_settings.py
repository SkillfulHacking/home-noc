"""connector settings and health state (M14, issue #17)

Revision ID: 0009_connector_settings
Revises: 0008_scan_policy_strict
Create Date: 2026-11-26 12:00:00

Adds ``connector_settings`` (non-secret). Downgrade drops it; stored
credentials live in ``connector_credentials`` and are untouched.
"""
import sqlalchemy as sa

from alembic import op

revision = "0009_connector_settings"
down_revision = "0008_scan_policy_strict"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "connector_settings" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "connector_settings",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("base_url", sa.String(255), nullable=True),
        sa.Column("site", sa.String(64), nullable=True),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_status", sa.String(16), nullable=True),
        sa.Column("last_error_code", sa.String(64), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_summary", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("connector_settings")
