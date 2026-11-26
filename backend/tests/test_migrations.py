from __future__ import annotations

import json
from pathlib import Path

import sqlalchemy as sa
from alembic.config import Config

from alembic import command
from app.config import settings


def _alembic_config() -> Config:
    backend_root = Path(__file__).resolve().parents[1]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "alembic"))
    # Preserve pytest logging when migrations run in-process.
    config.attributes["configure_logging"] = False
    return config


def test_populated_legacy_database_upgrade_and_downgrade(tmp_path):
    database_path = tmp_path / "legacy.sqlite"
    database_url = f"sqlite:///{database_path}"
    original_db_url = settings.db_url
    settings.db_url = database_url
    config = _alembic_config()

    try:
        command.upgrade(config, "0001_init_devices")
        engine = sa.create_engine(database_url)
        metadata = sa.MetaData()
        devices = sa.Table("devices", metadata, autoload_with=engine)
        with engine.begin() as connection:
            connection.execute(
                devices.insert(),
                [
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "hostname": "legacy-a",
                        "mac": "AA-BB-CC-DD-EE-FF",
                        "snmp": {"enabled": True, "community_or_user": "private"},
                    },
                    {
                        "id": "00000000-0000-0000-0000-000000000002",
                        "hostname": "legacy-b",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "snmp": None,
                    },
                ],
            )

        command.upgrade(config, "head")
        inspector = sa.inspect(engine)
        assert {"device_identities", "device_observations"}.issubset(
            inspector.get_table_names()
        )

        with engine.connect() as connection:
            identities = connection.execute(
                sa.text(
                    "SELECT device_id, external_id FROM device_identities "
                    "WHERE source = 'mac' ORDER BY device_id"
                )
            ).all()
            assert identities == [
                ("00000000-0000-0000-0000-000000000001", "aa:bb:cc:dd:ee:ff")
            ]
            stored_macs = connection.execute(
                sa.text("SELECT mac FROM devices ORDER BY id")
            ).scalars().all()
            assert stored_macs == ["aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"]
            # Duplicate legacy rows are preserved for explicit operator resolution;
            # the migration must never silently merge or delete assets.
            assert connection.execute(sa.text("SELECT count(*) FROM devices")).scalar_one() == 2
            snmp = connection.execute(
                sa.text("SELECT snmp FROM devices WHERE hostname = 'legacy-a'")
            ).scalar_one()
            assert "community_or_user" not in json.loads(snmp)

        command.downgrade(config, "0001_init_devices")
        inspector = sa.inspect(engine)
        assert "devices" in inspector.get_table_names()
        assert "device_identities" not in inspector.get_table_names()
        assert "device_observations" not in inspector.get_table_names()
    finally:
        settings.db_url = original_db_url


def test_connector_credentials_migration_round_trip_preserves_data(tmp_path):
    """0004 is additive: upgrade/downgrade/upgrade keeps devices and sessions."""
    database_url = f"sqlite:///{tmp_path / 'creds.sqlite'}"
    original_db_url = settings.db_url
    settings.db_url = database_url
    config = _alembic_config()

    try:
        command.upgrade(config, "0003_admin_sessions")
        engine = sa.create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(
                sa.text("INSERT INTO devices (id, hostname) VALUES ('dev-1', 'keep-me')")
            )
            connection.execute(
                sa.text(
                    "INSERT INTO admin_sessions (id, token_hash, csrf_hash, username, "
                    "created_at, last_seen_at, expires_at) VALUES "
                    "('s1', 'th', 'ch', 'admin', '2026-01-01 00:00:00', "
                    "'2026-01-01 00:00:00', '2999-01-01 00:00:00')"
                )
            )

        def assert_preserved():
            with engine.connect() as connection:
                assert connection.execute(
                    sa.text("SELECT hostname FROM devices WHERE id = 'dev-1'")
                ).scalar_one() == "keep-me"
                assert connection.execute(
                    sa.text("SELECT username FROM admin_sessions WHERE id = 's1'")
                ).scalar_one() == "admin"

        command.upgrade(config, "head")
        inspector = sa.inspect(engine)
        assert "connector_credentials" in inspector.get_table_names()
        columns = {c["name"] for c in inspector.get_columns("connector_credentials")}
        assert {"ciphertext", "enc_version", "meta", "scope_key"}.issubset(columns)
        # No place for a plaintext secret or the key to live.
        assert not {"secret", "token", "password", "key", "plaintext"} & columns
        assert_preserved()

        command.downgrade(config, "0003_admin_sessions")
        assert "connector_credentials" not in sa.inspect(engine).get_table_names()
        assert_preserved()

        command.upgrade(config, "head")
        assert "connector_credentials" in sa.inspect(engine).get_table_names()
        assert_preserved()
        engine.dispose()
    finally:
        settings.db_url = original_db_url


def test_admin_sessions_migration_round_trip(tmp_path):
    """0003 creates the session store and 0002 removes it cleanly."""
    database_path = tmp_path / "sessions.sqlite"
    database_url = f"sqlite:///{database_path}"
    original_db_url = settings.db_url
    settings.db_url = database_url
    config = _alembic_config()

    try:
        command.upgrade(config, "head")
        engine = sa.create_engine(database_url)
        inspector = sa.inspect(engine)
        assert "admin_sessions" in inspector.get_table_names()

        columns = {c["name"] for c in inspector.get_columns("admin_sessions")}
        assert columns == {
            "id",
            "token_hash",
            "csrf_hash",
            "username",
            "created_at",
            "last_seen_at",
            "expires_at",
        }
        # The raw password must have no column to live in.
        assert not {"password", "password_hash", "token", "csrf_token"} & columns

        indexes = {ix["name"]: ix for ix in inspector.get_indexes("admin_sessions")}
        # SQLite reports uniqueness as 1 rather than True.
        assert indexes["ix_admin_sessions_token_hash"]["unique"]

        command.downgrade(config, "0002_device_identities_observations")
        assert "admin_sessions" not in sa.inspect(engine).get_table_names()
        engine.dispose()
    finally:
        settings.db_url = original_db_url


def test_connector_settings_migration_round_trip_keeps_credentials(tmp_path):
    """0009 adds connector_settings; downgrade drops only it, never credentials."""
    database_url = f"sqlite:///{tmp_path / 'settings.sqlite'}"
    original_db_url = settings.db_url
    settings.db_url = database_url
    config = _alembic_config()
    try:
        command.upgrade(config, "0008_scan_policy_strict")
        engine = sa.create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO connector_credentials (id, scope_key, connector, "
                    "credential_type, enc_version, ciphertext, meta, created_at, updated_at) "
                    "VALUES ('c1', 'connector:unifi', 'unifi', 'unifi_api_token', 1, "
                    "x'00', '{}', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                )
            )
        command.upgrade(config, "head")
        assert "connector_settings" in sa.inspect(engine).get_table_names()
        command.downgrade(config, "0008_scan_policy_strict")
        names = sa.inspect(engine).get_table_names()
        assert "connector_settings" not in names and "connector_credentials" in names
        with engine.connect() as connection:
            assert connection.execute(
                sa.text("SELECT id FROM connector_credentials")
            ).scalar_one() == "c1"
        command.upgrade(config, "head")
        engine.dispose()
    finally:
        settings.db_url = original_db_url


def test_schedules_migration_round_trip_keeps_jobs(tmp_path):
    """0010 adds schedules; downgrade drops only it and leaves queued jobs alone."""
    database_url = f"sqlite:///{tmp_path / 'schedules.sqlite'}"
    original_db_url = settings.db_url
    settings.db_url = database_url
    config = _alembic_config()
    try:
        command.upgrade(config, "0009_connector_settings")
        engine = sa.create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(sa.text(
                "INSERT INTO scan_jobs (id, kind, profile, targets, status, created_by, "
                "created_at, updated_at, available_at, attempts, max_attempts, "
                "cancel_requested, progress_total, progress_done) VALUES ('j1', 'scan', "
                "'discovery', '{\"v\": []}', 'queued', 'op', '2026-01-01 00:00:00', "
                "'2026-01-01 00:00:00', '2026-01-01 00:00:00', 0, 3, 0, 0, 0)"))
        command.upgrade(config, "head")
        assert "schedules" in sa.inspect(engine).get_table_names()
        command.downgrade(config, "0009_connector_settings")
        assert "schedules" not in sa.inspect(engine).get_table_names()
        with engine.connect() as connection:
            assert connection.execute(sa.text("SELECT id FROM scan_jobs")).scalar_one() == "j1"
        command.upgrade(config, "head")
        engine.dispose()
    finally:
        settings.db_url = original_db_url


def test_device_health_migration_round_trip_keeps_devices(tmp_path):
    """0011 adds health tables; downgrade drops only them."""
    database_url = f"sqlite:///{tmp_path / 'health.sqlite'}"
    original_db_url = settings.db_url
    settings.db_url = database_url
    config = _alembic_config()
    try:
        command.upgrade(config, "0010_schedules")
        engine = sa.create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(sa.text("INSERT INTO devices (id, hostname) VALUES ('d1', 'keep')"))
        command.upgrade(config, "head")
        names = set(sa.inspect(engine).get_table_names())
        assert {"device_health", "health_snapshots"} <= names
        command.downgrade(config, "0010_schedules")
        names = set(sa.inspect(engine).get_table_names())
        assert not {"device_health", "health_snapshots"} & names
        with engine.connect() as connection:
            hostname = connection.execute(sa.text("SELECT hostname FROM devices")).scalar_one()
            assert hostname == "keep"
        command.upgrade(config, "head")
        engine.dispose()
    finally:
        settings.db_url = original_db_url


def test_events_migration_round_trip_keeps_devices(tmp_path):
    """0012 adds events; downgrade drops only that table."""
    database_url = f"sqlite:///{tmp_path / 'events.sqlite'}"
    original_db_url = settings.db_url
    settings.db_url = database_url
    config = _alembic_config()
    try:
        command.upgrade(config, "0011_device_health")
        engine = sa.create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(sa.text("INSERT INTO devices (id, hostname) VALUES ('d1', 'keep')"))
        command.upgrade(config, "head")
        assert "events" in sa.inspect(engine).get_table_names()
        command.downgrade(config, "0011_device_health")
        assert "events" not in sa.inspect(engine).get_table_names()
        with engine.connect() as connection:
            hostname = connection.execute(sa.text("SELECT hostname FROM devices")).scalar_one()
            assert hostname == "keep"
        command.upgrade(config, "head")
        engine.dispose()
    finally:
        settings.db_url = original_db_url
