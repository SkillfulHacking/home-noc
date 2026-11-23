"""0006 adds scan_jobs/job_events without touching existing data (M09)."""
from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic.config import Config

from alembic import command
from app.config import settings


def _config() -> Config:
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    config.attributes["configure_logging"] = False
    return config


def test_scan_jobs_migration_round_trip_and_matches_models(tmp_path):
    url = f"sqlite:///{tmp_path / 'jobs.sqlite'}"
    original = settings.db_url
    settings.db_url = url
    config = _config()
    try:
        command.upgrade(config, "0005_credential_key_verifier")
        engine = sa.create_engine(url)
        with engine.begin() as conn:
            conn.execute(sa.text("INSERT INTO devices (id, hostname) VALUES ('d1', 'keep-me')"))

        command.upgrade(config, "head")
        inspector = sa.inspect(engine)
        assert {"scan_jobs", "job_events"}.issubset(inspector.get_table_names())

        from app.models import JobEvent, ScanJob
        assert {c["name"] for c in inspector.get_columns("scan_jobs")} == {
            c.name for c in ScanJob.__table__.columns
        }
        assert {c["name"] for c in inspector.get_columns("job_events")} == {
            c.name for c in JobEvent.__table__.columns
        }
        # Nowhere for a credential to live.
        cols = {c["name"] for c in inspector.get_columns("scan_jobs")}
        assert not {"password", "secret", "token", "credential"} & cols

        # The status constraint and the event cascade are real in the migrated schema.
        with engine.connect() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text(
                "INSERT INTO scan_jobs (id, kind, profile, targets, status, created_by, "
                "created_at, updated_at, available_at, attempts, max_attempts, "
                "cancel_requested, progress_total, progress_done) VALUES "
                "('j1','scan','discovery','{}','queued','a','2026-01-01','2026-01-01',"
                "'2026-01-01',0,3,0,0,0)"
            ))
            conn.execute(sa.text(
                "INSERT INTO job_events (job_id, created_at, level, type, message) "
                "VALUES ('j1','2026-01-01','info','queued','m')"
            ))
            conn.execute(sa.text("DELETE FROM scan_jobs WHERE id='j1'"))
            assert conn.execute(sa.text("SELECT count(*) FROM job_events")).scalar_one() == 0
            try:
                conn.execute(sa.text(
                    "INSERT INTO scan_jobs (id, kind, profile, targets, status, created_by, "
                    "created_at, updated_at, available_at, attempts, max_attempts, "
                    "cancel_requested, progress_total, progress_done) VALUES "
                    "('j2','scan','discovery','{}','bogus','a','2026-01-01','2026-01-01',"
                    "'2026-01-01',0,3,0,0,0)"
                ))
            except sa.exc.IntegrityError:
                pass
            else:
                raise AssertionError("invalid status accepted")
            conn.rollback()

        command.downgrade(config, "0005_credential_key_verifier")
        names = set(sa.inspect(engine).get_table_names())
        assert "scan_jobs" not in names and "job_events" not in names
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT hostname FROM devices")).scalar_one() == "keep-me"

        command.upgrade(config, "head")
        assert "scan_jobs" in sa.inspect(engine).get_table_names()
        engine.dispose()
    finally:
        settings.db_url = original
