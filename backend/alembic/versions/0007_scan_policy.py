"""runtime scan policy and its audit trail (M08A, issue #66)

Revision ID: 0007_scan_policy
Revises: 0006_scan_jobs
Create Date: 2026-11-24 09:00:00

Additive: creates ``scan_policy`` (single row) and ``scan_policy_audit``. No
existing table is altered. The single policy row is seeded here so a migrated
database never boots without one (the application fails closed if it is
missing):

* **Fresh install** (explicit evidence: ``env.py`` found a database with no
  tables before this run): private RFC1918 scanning is enabled; the
  administrator must still pick explicit targets. Public scanning is off.
  Ambiguous situations -- including an existing but *empty* schema -- are
  upgrades and stay denied.
* **Upgrade with a non-empty SCAN_ALLOWED_CIDRS**: the operator already
  authorized scanning through the environment, so private scanning is
  enabled and that environment list stays an immutable ceiling.
* **Upgrade with an empty/unset SCAN_ALLOWED_CIDRS**: previously every scan was
  rejected. That is preserved -- private scanning is seeded *disabled* and an
  administrator must enable it deliberately.

Public scanning is never seeded as enabled, even if SCAN_ALLOW_PUBLIC was set.

Downgrade drops both tables (policy history is discarded; inventory is not
touched). After a downgrade the older release authorizes scans from the
environment alone, exactly as before.
"""
from datetime import UTC, datetime

import sqlalchemy as sa

from alembic import op

revision = "0007_scan_policy"
down_revision = "0006_scan_jobs"
branch_labels = None
depends_on = None

def _is_fresh_bootstrap() -> bool:
    """True only with explicit evidence: ``alembic/env.py`` saw a database with no
    tables at all before this run. Anything ambiguous (marker missing because the
    migration was driven some other way, an existing schema -- even an empty one --
    or a pre-Alembic database) is treated as an upgrade and stays denied."""
    from alembic import context

    return context.config.attributes.get("db_was_empty") is True


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())

    if "scan_policy" not in tables:
        op.create_table(
            "scan_policy",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("private_enabled", sa.Boolean(), nullable=False),
            sa.Column("private_allowlist", sa.JSON(), nullable=False),
            sa.Column("public_enabled", sa.Boolean(), nullable=False),
            sa.Column("public_allowlist", sa.JSON(), nullable=False),
            sa.Column("exclusions", sa.JSON(), nullable=False),
            sa.Column("bootstrap_origin", sa.String(length=24), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_by", sa.String(length=255), nullable=False),
            sa.CheckConstraint("id = 1", name="ck_scan_policy_singleton"),
            sa.CheckConstraint("revision >= 1", name="ck_scan_policy_revision"),
        )
        from app.config import settings  # deferred: only needed to classify the install

        env_scope = bool((settings.scan_allowed_cidrs_raw or "").strip())
        if _is_fresh_bootstrap():
            origin, private_enabled = "fresh", True
        elif env_scope:
            origin, private_enabled = "upgrade_env_scope", True
        else:
            origin, private_enabled = "upgrade", False
        bind.execute(
            sa.text(
                "INSERT INTO scan_policy (id, revision, private_enabled, private_allowlist, "
                "public_enabled, public_allowlist, exclusions, bootstrap_origin, "
                "updated_at, updated_by) VALUES (1, 1, :pe, :empty, 0, :empty, :empty, "
                ":origin, :now, 'migration')"
            ),
            {
                "pe": private_enabled,
                "empty": '{"v": []}',
                "origin": origin,
                # SQLite DATETIME text form, in UTC.
                "now": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f"),
            },
        )

    if "scan_policy_audit" not in tables:
        op.create_table(
            "scan_policy_audit",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("actor", sa.String(length=255), nullable=False),
            sa.Column("outcome", sa.String(length=48), nullable=False),
            sa.Column("prior_revision", sa.Integer(), nullable=True),
            sa.Column("new_revision", sa.Integer(), nullable=True),
            sa.Column("prior", sa.JSON(), nullable=True),
            sa.Column("new", sa.JSON(), nullable=True),
        )


def downgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "scan_policy_audit" in tables:
        op.drop_table("scan_policy_audit")
    if "scan_policy" in tables:
        op.drop_table("scan_policy")
