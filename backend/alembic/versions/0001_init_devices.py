"""init devices

Revision ID: 0001_init_devices
Revises:
Create Date: 2025-10-30 00:00:00
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0001_init_devices"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    tables = set(inspector.get_table_names())
    if "devices" not in tables:
        op.create_table(
            "devices",
            sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
            sa.Column("hostname", sa.String(length=255), nullable=False),
            sa.Column("ip", sa.JSON(), nullable=True),
            sa.Column("mac", sa.String(length=32), nullable=True),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("discovery_method", sa.String(length=16), nullable=True),
            sa.Column("vendor", sa.String(length=255), nullable=True),
            sa.Column("model", sa.String(length=255), nullable=True),
            sa.Column("os", sa.String(length=255), nullable=True),
            sa.Column("serial", sa.String(length=255), nullable=True),
            sa.Column("location", sa.String(length=255), nullable=True),
            sa.Column("roles", sa.JSON(), nullable=True),
            sa.Column("ports", sa.JSON(), nullable=True),
            sa.Column("snmp", sa.JSON(), nullable=True),
            sa.Column("api", sa.JSON(), nullable=True),
            sa.Column("notes", sa.String(length=4096), nullable=True),
        )

    # Ensure index exists
    existing_indexes = []
    if "devices" in tables:
        try:
            existing_indexes = [ix["name"] for ix in inspector.get_indexes("devices")]
        except Exception:
            existing_indexes = []

    if "ix_devices_hostname" not in existing_indexes:
        op.create_index("ix_devices_hostname", "devices", ["hostname"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "devices" in tables:
        # Drop index if present
        try:
            existing_indexes = [ix["name"] for ix in inspector.get_indexes("devices")]
        except Exception:
            existing_indexes = []
        if "ix_devices_hostname" in existing_indexes:
            op.drop_index("ix_devices_hostname", table_name="devices")

        op.drop_table("devices")
