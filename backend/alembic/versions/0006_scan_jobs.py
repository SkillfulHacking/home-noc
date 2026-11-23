"""durable scan jobs and job events (M09)

Revision ID: 0006_scan_jobs
Revises: 0005_credential_key_verifier
Create Date: 2026-11-22 03:00:00

Purely additive: no existing table is altered. ``scan_jobs`` carries the job
lifecycle and SQLite lease columns; ``job_events`` is an append-only log whose
integer id is the frontend polling cursor. Neither table can hold credentials.
"""
import sqlalchemy as sa

from alembic import op

revision = "0006_scan_jobs"
down_revision = "0005_credential_key_verifier"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())

    if "scan_jobs" not in tables:
        op.create_table(
            "scan_jobs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("kind", sa.String(length=16), nullable=False),
            sa.Column("profile", sa.String(length=16), nullable=False),
            sa.Column("targets", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("created_by", sa.String(length=255), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("max_attempts", sa.Integer(), nullable=False),
            sa.Column("lease_owner", sa.String(length=128), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("runner_pid", sa.Integer(), nullable=True),
            sa.Column("cancel_requested", sa.Boolean(), nullable=False),
            sa.Column("progress_total", sa.Integer(), nullable=False),
            sa.Column("progress_done", sa.Integer(), nullable=False),
            sa.Column("error_code", sa.String(length=32), nullable=True),
            sa.Column("error_message", sa.String(length=512), nullable=True),
            sa.Column("result", sa.JSON(), nullable=True),
            sa.CheckConstraint(
                "status IN ('queued','running','cancelling','succeeded','failed','cancelled')",
                name="ck_scan_jobs_status",
            ),
        )
        op.create_index(
            "ix_scan_jobs_status_available_at", "scan_jobs", ["status", "available_at"]
        )

    if "job_events" not in tables:
        op.create_table(
            "job_events",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column(
                "job_id",
                sa.String(length=36),
                sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("level", sa.String(length=8), nullable=False),
            sa.Column("type", sa.String(length=32), nullable=False),
            sa.Column("message", sa.String(length=512), nullable=False),
            sa.Column("data", sa.JSON(), nullable=True),
            sqlite_autoincrement=True,
        )
        op.create_index("ix_job_events_job_id_id", "job_events", ["job_id", "id"])


def downgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    # Dropping discards job history; inventory tables are untouched.
    if "job_events" in tables:
        op.drop_index("ix_job_events_job_id_id", table_name="job_events")
        op.drop_table("job_events")
    if "scan_jobs" in tables:
        op.drop_index("ix_scan_jobs_status_available_at", table_name="scan_jobs")
        op.drop_table("scan_jobs")
