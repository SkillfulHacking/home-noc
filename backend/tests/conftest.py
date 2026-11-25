# backend/tests/conftest.py
from __future__ import annotations

import base64
import os

import pytest

# Set test environment variables before any app imports
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DB_URL", "sqlite:///:memory:")

# A throwaway admin credential that exists only for the test session. The
# verifier uses a deliberately low PBKDF2 work factor so the suite stays
# fast; app.auth refuses work factors this low in production.
TEST_ADMIN_USERNAME = "test-admin"
# noqa rationale: a throwaway fixture credential, not a real or default secret.
TEST_ADMIN_PASSWORD = "correct horse battery staple"  # noqa: S105
TEST_PBKDF2_ITERATIONS = 1_000


@pytest.fixture(autouse=True)
def admin_credentials(monkeypatch):
    """Configure a per-test admin verifier and reset the login throttle."""
    from app import auth
    from app.config import settings

    verifier = auth.hash_password(TEST_ADMIN_PASSWORD, iterations=TEST_PBKDF2_ITERATIONS)
    monkeypatch.setattr(settings, "admin_username", TEST_ADMIN_USERNAME)
    monkeypatch.setattr(settings, "admin_password_hash", verifier)
    auth.clear_login_throttle()
    yield
    auth.clear_login_throttle()


# A throwaway AES-256 key (32 random bytes, urlsafe-base64) generated fresh
# for each test run; it is never written anywhere and protects nothing real.
TEST_CREDENTIAL_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


@pytest.fixture(autouse=True)
def credential_key(monkeypatch):
    """Provision a per-test credential encryption key."""
    from pydantic import SecretStr

    from app.config import settings

    monkeypatch.setattr(settings, "credential_encryption_key", SecretStr(TEST_CREDENTIAL_KEY))
    monkeypatch.setattr(settings, "credential_encryption_key_file", None)
    yield


@pytest.fixture(autouse=True)
def reset_scan_policy():
    """Each test starts from a fresh-install policy (lazily seeded in non-production)
    and leaves none behind, because the in-memory database outlives a test."""
    yield
    from sqlalchemy.exc import SQLAlchemyError

    from app.db import SessionLocal
    from app.models import ScanPolicy, ScanPolicyAudit

    try:
        with SessionLocal() as db:
            db.query(ScanPolicyAudit).delete()
            db.query(ScanPolicy).delete()
            db.commit()
    except SQLAlchemyError:
        pass  # table not created in this test's process yet


def set_policy(db, **changes):
    """Test helper: write policy fields directly (bumping the revision)."""
    from app import scan_policy

    current = scan_policy.load_policy(db)
    cfg = {**current.config(), **changes}
    return scan_policy.update_policy(
        db, actor="test-setup", expected_revision=current.revision,
        confirm_broadening=True, confirm_public=True, **cfg,
    )


@pytest.fixture
def anon_client():
    """An unauthenticated client, for negative/fail-closed assertions."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


def login(client, username: str = TEST_ADMIN_USERNAME, password: str = TEST_ADMIN_PASSWORD):
    """Sign in and return the CSRF header required for unsafe methods."""
    from app.security import CSRF_COOKIE_NAME

    resp = client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return {"X-CSRF-Token": client.cookies[CSRF_COOKIE_NAME]}


@pytest.fixture
def client(anon_client):
    """A signed-in client.

    Authentication is the default for this suite because every inventory and
    scan route now requires a session; tests that assert the fail-closed
    behaviour ask for ``anon_client`` instead. ``client.csrf_headers`` holds
    the header that unsafe methods must echo back.
    """
    anon_client.csrf_headers = login(anon_client)
    return anon_client


@pytest.fixture
def second_client():
    """A second, independent client (separate cookie jar, same app/database).

    Needed to prove cross-session isolation: ``client`` and ``anon_client``
    deliberately share one jar, so they cannot represent two operators.
    """
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def job_env(monkeypatch):
    """Private-range scan scope and fast, bounded worker settings (M09).

    Nothing here points at a real network: tests substitute a fake scanner.
    """
    from app.config import settings

    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "10.77.0.0/24")
    monkeypatch.setattr(settings, "worker_max_concurrent_jobs", 1)
    monkeypatch.setattr(settings, "scan_max_active_jobs", 5)
    monkeypatch.setattr(settings, "worker_lease_seconds", 3)
    monkeypatch.setattr(settings, "worker_kill_grace_seconds", 1.0)
    monkeypatch.setattr(settings, "scan_job_max_attempts", 3)
    monkeypatch.setattr(settings, "scan_job_retry_backoff_seconds", 0.0)
    return settings


@pytest.fixture
def job_session_factory(tmp_path):
    """A file-backed SQLite database, so worker threads get real connections."""
    from sqlalchemy.orm import sessionmaker

    from app import models  # noqa: F401
    from app.db import Base, _make_engine

    eng = _make_engine(f"sqlite:///{tmp_path / 'jobs.sqlite'}")
    Base.metadata.create_all(eng)
    yield sessionmaker(bind=eng, autocommit=False, autoflush=False)
    eng.dispose()
