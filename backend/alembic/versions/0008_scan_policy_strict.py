"""explicit strict private mode for the scan policy (M08A, issue #66)

Revision ID: 0008_scan_policy_strict
Revises: 0007_scan_policy
Create Date: 2026-11-25 09:00:00

Adds ``scan_policy.private_strict``. Before this column, a non-empty private
allowlist implicitly meant "only these ranges"; that authorization is preserved
exactly: rows with a non-empty allowlist become ``private_strict = 1``, every
other row becomes ``0`` (all RFC1918, as before). No authorization is widened.

Downgrade drops the column. A strict row with an *empty* list (nothing
authorized) would then read as "all RFC1918" in the older semantics, so the
downgrade first disables private scanning on such rows -- never widening.
"""
import sqlalchemy as sa

from alembic import op

revision = "0008_scan_policy_strict"
down_revision = "0007_scan_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("scan_policy")}
    if "private_strict" in columns:
        return
    with op.batch_alter_table("scan_policy") as batch:
        batch.add_column(
            sa.Column(
                "private_strict", sa.Boolean(), nullable=False, server_default=sa.false()
            )
        )
    rows = bind.execute(sa.text("SELECT id, private_allowlist FROM scan_policy")).all()
    import json

    for row_id, raw in rows:
        value = json.loads(raw) if isinstance(raw, str) else raw
        if (value or {}).get("v"):
            bind.execute(
                sa.text("UPDATE scan_policy SET private_strict = 1 WHERE id = :i"), {"i": row_id}
            )


def downgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("scan_policy")}
    if "private_strict" not in columns:
        return
    # Strict + empty list authorized nothing; without the column it would mean
    # "all RFC1918". Keep it denied instead.
    bind.execute(sa.text(
        "UPDATE scan_policy SET private_enabled = 0 WHERE private_strict = 1 "
        "AND private_allowlist LIKE '%[]%'"
    ))
    with op.batch_alter_table("scan_policy") as batch:
        batch.drop_column("private_strict")
