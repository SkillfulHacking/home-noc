"""admin session store for fail-closed operator authentication (M03)

Revision ID: 0003_admin_sessions
Revises: 0002_device_identities_observations
Create Date: 2026-11-22 00:00:00
"""
import sqlalchemy as sa

from alembic import op

revision = "0003_admin_sessions"
down_revision = "0002_device_identities_observations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "admin_sessions" in set(inspector.get_table_names()):
        return

    # Only token *digests* are stored, so a database read cannot be replayed
    # as a live session.
    op.create_table(
        "admin_sessions",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_hash", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_admin_sessions_token_hash", "admin_sessions", ["token_hash"], unique=True
    )
    op.create_index("ix_admin_sessions_expires_at", "admin_sessions", ["expires_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "admin_sessions" not in set(inspector.get_table_names()):
        return
    existing = {ix["name"] for ix in inspector.get_indexes("admin_sessions")}
    for name in ("ix_admin_sessions_expires_at", "ix_admin_sessions_token_hash"):
        if name in existing:
            op.drop_index(name, table_name="admin_sessions")
    op.drop_table("admin_sessions")
