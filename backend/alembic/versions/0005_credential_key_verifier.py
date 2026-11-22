"""credential master-key verifier (M04)

Revision ID: 0005_credential_key_verifier
Revises: 0004_connector_credentials
Create Date: 2026-11-22 02:00:00

Adds a single-row table holding a versioned, salted HMAC-SHA256 verifier that
binds the database to the credential master key. The key itself is never
stored and this migration never needs it: a database that already holds
credentials but has no verifier is bound at runtime, and only after every
existing ciphertext has been authenticated with the supplied key.
"""
import sqlalchemy as sa

from alembic import op

revision = "0005_credential_key_verifier"
down_revision = "0004_connector_credentials"
branch_labels = None
depends_on = None

TABLE = "credential_key_verifier"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if TABLE in set(inspector.get_table_names()):
        return
    # Purely additive; connector_credentials rows are untouched.
    op.create_table(
        TABLE,
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("salt", sa.LargeBinary(), nullable=False),
        sa.Column("verifier", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_credential_key_verifier_singleton"),
        sa.CheckConstraint("length(salt) = 16", name="ck_credential_key_verifier_salt"),
        sa.CheckConstraint("length(verifier) = 32", name="ck_credential_key_verifier_len"),
    )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if TABLE not in set(inspector.get_table_names()):
        return
    # Removes the key binding only. Credential ciphertext is kept; after a
    # re-upgrade the binding is re-established by authenticating those rows.
    op.drop_table(TABLE)
