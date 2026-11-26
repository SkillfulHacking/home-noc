# backend/alembic/env.py
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root on path for `app.*` imports
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging.config import fileConfig  # noqa: E402

from sqlalchemy import engine_from_config, inspect, pool  # noqa: E402

from alembic import context  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import Base  # noqa: E402
from app.models import (  # noqa: F401,E402
    AdminSession,
    Device,
    DeviceIdentity,
    DeviceObservation,
)

config = context.config
# Embedded callers can manage their own logging configuration.
if (
    config.config_file_name is not None
    and config.attributes.get("configure_logging", True)
):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section) or {}
    cfg["sqlalchemy.url"] = settings.database_url

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        # Explicit fresh-bootstrap evidence for migrations that must tell a brand
        # new install from an upgrade (0007 scan policy): the database had no
        # tables at all before this run. An existing install -- even one with no
        # rows -- always has tables, so it is never mistaken for fresh.
        config.attributes["db_was_empty"] = not inspect(connection).get_table_names()

        # Schema inspection triggers SQLAlchemy autobegin.
        # End the read-only transaction before Alembic takes ownership.
        connection.rollback()

        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
