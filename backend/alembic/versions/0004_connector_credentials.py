"""encrypted connector credential store (M04)

Revision ID: 0004_connector_credentials
Revises: 0003_admin_sessions
Create Date: 2026-11-22 01:00:00
"""
import sqlalchemy as sa

from alembic import op

revision = "0004_connector_credentials"
down_revision = "0003_admin_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "connector_credentials" in set(inspector.get_table_names()):
        return

    # Only AES-256-GCM envelopes and non-secret metadata live here. The
    # encryption key is supplied by configuration and is never stored.
    # Purely additive: devices, observations and sessions are untouched.
    op.create_table(
        "connector_credentials",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scope_key", sa.String(length=128), nullable=False),
        sa.Column(
            "device_id",
            sa.String(length=36),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("connector", sa.String(length=64), nullable=True),
        sa.Column("credential_type", sa.String(length=32), nullable=False),
        sa.Column("enc_version", sa.Integer(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "scope_key", "credential_type", name="uq_connector_credential_scope_type"
        ),
        sa.CheckConstraint(
            "((device_id IS NULL) + (connector IS NULL)) = 1",
            name="ck_connector_credential_one_scope",
        ),
    )
    op.create_index(
        "ix_connector_credentials_device_id", "connector_credentials", ["device_id"]
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "connector_credentials" not in set(inspector.get_table_names()):
        return
    existing = {ix["name"] for ix in inspector.get_indexes("connector_credentials")}
    if "ix_connector_credentials_device_id" in existing:
        op.drop_index("ix_connector_credentials_device_id", table_name="connector_credentials")
    # Dropping the table discards every stored ciphertext; credentials must be
    # re-entered after a re-upgrade.
    op.drop_table("connector_credentials")
