"""vulnerability findings and lifecycle audit trail (M18, issue #21)

Revision ID: 0013_findings
Revises: 0012_events
Create Date: 2026-11-26 21:00:00

Adds ``findings`` and ``finding_events``. Downgrade drops only those tables.
"""
import sqlalchemy as sa

from alembic import op

revision = "0013_findings"
down_revision = "0012_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "findings" not in tables:
        op.create_table(
            "findings",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("fingerprint", sa.String(64), nullable=False),
            sa.Column("template_id", sa.String(128), nullable=False),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("severity", sa.String(10), nullable=False),
            sa.Column("status", sa.String(12), nullable=False, server_default="open"),
            sa.Column("host", sa.String(64), nullable=False),
            sa.Column("port", sa.Integer(), nullable=False),
            sa.Column("scheme", sa.String(8), nullable=False),
            sa.Column("path", sa.String(200), nullable=False, server_default="/"),
            sa.Column("matcher_name", sa.String(100), nullable=True),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("suppressed_reason", sa.String(300), nullable=True),
            sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("missed_runs", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_job_id", sa.String(36), nullable=True),
            sa.Column("template_version", sa.String(32), nullable=True),
            sa.Column("scanner_version", sa.String(32), nullable=True),
            sa.Column("details", sa.JSON(), nullable=False),
            sa.UniqueConstraint("device_id", "fingerprint", name="uq_finding_device_fingerprint"),
        )
        op.create_index("ix_findings_device_id", "findings", ["device_id"])
        op.create_index("ix_findings_status_severity", "findings", ["status", "severity"])
    if "finding_events" not in tables:
        op.create_table(
            "finding_events",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("type", sa.String(16), nullable=False),
            sa.Column("job_id", sa.String(36), nullable=True),
            sa.Column("actor", sa.String(255), nullable=True),
            sa.Column("note", sa.String(300), nullable=True),
        )
        op.create_index("ix_finding_events_finding_at", "finding_events", ["finding_id", "at"])


def downgrade() -> None:
    op.drop_index("ix_finding_events_finding_at", table_name="finding_events")
    op.drop_table("finding_events")
    op.drop_index("ix_findings_status_severity", table_name="findings")
    op.drop_index("ix_findings_device_id", table_name="findings")
    op.drop_table("findings")
