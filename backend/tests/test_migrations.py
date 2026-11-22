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
