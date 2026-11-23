# backend/tests/test_auth.py
"""Negative and positive coverage for fail-closed admin auth (M03, #6)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from conftest import TEST_ADMIN_PASSWORD, TEST_ADMIN_USERNAME, login

from app import auth
from app.config import settings
from app.db import SessionLocal
from app.models import AdminSession
from app.security import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME

LOGIN = "/api/v1/auth/login"
LOGOUT = "/api/v1/auth/logout"
SESSION = "/api/v1/auth/session"
DEVICES = "/api/v1/devices"
PING_SWEEP = "/api/v1/scans/ping-sweep?targets=192.0.2.1&dry_run=true"

# Every route that exposes inventory, scans or session state. Anonymous
# access to any of these is a fail-open regression.
PROTECTED_READS = [DEVICES, f"{DEVICES}/does-not-exist", SESSION]


# ---------------------------------------------------------------------------
# Fail closed: anonymous access
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", PROTECTED_READS)
def test_anonymous_reads_are_rejected(anon_client, path):
    assert anon_client.get(path).status_code == 401


def test_anonymous_mutations_are_rejected(anon_client):
    assert anon_client.post(DEVICES, json={"hostname": "x"}).status_code == 401
    assert anon_client.put(f"{DEVICES}/abc", json={"hostname": "x"}).status_code == 401
    assert anon_client.patch(f"{DEVICES}/abc", json={"hostname": "x"}).status_code == 401
    assert anon_client.delete(f"{DEVICES}/abc").status_code == 401


def test_anonymous_scan_is_rejected(anon_client):
    assert anon_client.post(PING_SWEEP).status_code == 401


def test_health_and_version_stay_anonymous(anon_client):
    """Container healthchecks must not require a credential."""
    assert anon_client.get("/health").status_code == 200
    assert anon_client.get("/version").status_code == 200


def test_a_stale_or_forged_cookie_is_rejected(anon_client):
    anon_client.cookies.set(SESSION_COOKIE_NAME, "not-a-real-session-token")
    assert anon_client.get(DEVICES).status_code == 401


def test_api_key_header_is_no_longer_a_bypass(anon_client):
    """The M01/M02-era shared key must not authenticate anything."""
    for header in ({"X-API-Key": "changeme-please-32bytes-min"}, {"X-API-Key": ""}):
        assert anon_client.get(DEVICES, headers=header).status_code == 401
    assert not hasattr(settings, "api_key")


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def test_login_succeeds_and_sets_hardened_cookies(anon_client):
    resp = anon_client.post(
        LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD}
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == TEST_ADMIN_USERNAME

    cookies = {}
    for raw in resp.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0]
        cookies[name] = raw.lower()

    assert "httponly" in cookies[SESSION_COOKIE_NAME]
    assert "samesite=strict" in cookies[SESSION_COOKIE_NAME]
    assert "path=/" in cookies[SESSION_COOKIE_NAME]
    # The SPA must be able to read the CSRF token to echo it back.
    assert "httponly" not in cookies[CSRF_COOKIE_NAME]
    assert "samesite=strict" in cookies[CSRF_COOKIE_NAME]


def test_session_cookie_is_secure_when_configured(anon_client, monkeypatch):
    monkeypatch.setattr(settings, "session_cookie_secure_raw", True)
    resp = anon_client.post(
        LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD}
    )
    assert resp.status_code == 200
    for raw in resp.headers.get_list("set-cookie"):
        assert "secure" in raw.lower()


def test_wrong_password_is_rejected(anon_client):
    resp = anon_client.post(
        LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": "wrong-password-123"}
    )
    assert resp.status_code == 401
    assert SESSION_COOKIE_NAME not in resp.cookies
    assert anon_client.get(DEVICES).status_code == 401


def test_unknown_user_is_indistinguishable_from_a_wrong_password(anon_client):
    wrong_user = anon_client.post(
        LOGIN, json={"username": "someone-else", "password": TEST_ADMIN_PASSWORD}
    )
    wrong_pass = anon_client.post(
        LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": "nope-nope-nope"}
    )
    assert wrong_user.status_code == wrong_pass.status_code == 401
    assert wrong_user.json() == wrong_pass.json()


def test_login_is_impossible_without_a_configured_verifier(anon_client, monkeypatch):
    """Dev/test may start unconfigured, but it must never authenticate."""
    monkeypatch.setattr(settings, "admin_password_hash", None)
    resp = anon_client.post(
        LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD}
    )
    assert resp.status_code == 401
    assert anon_client.get(DEVICES).status_code == 401


def test_repeated_failures_lock_the_account_out(anon_client):
    for _ in range(auth.MAX_FAILED_ATTEMPTS):
        assert (
            anon_client.post(
                LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": "bad-password-1"}
            ).status_code
            == 401
        )
    # The correct password is now refused too, so an attacker cannot simply
    # keep guessing.
    locked = anon_client.post(
        LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD}
    )
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0


def test_login_never_echoes_the_password(anon_client):
    resp = anon_client.post(
        LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": "super-secret-value"}
    )
    assert "super-secret-value" not in resp.text


def test_login_does_not_log_the_password(anon_client, caplog):
    with caplog.at_level("DEBUG"):
        anon_client.post(
            LOGIN, json={"username": TEST_ADMIN_USERNAME, "password": "leaky-secret-value"}
        )
    assert "leaky-secret-value" not in caplog.text


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------


def test_session_endpoint_reports_the_signed_in_operator(client):
    body = client.get(SESSION).json()
    assert body["username"] == TEST_ADMIN_USERNAME
    assert body["expires_at"]


def test_logout_revokes_the_session_server_side(client):
    stolen = client.cookies[SESSION_COOKIE_NAME]
    assert client.post(LOGOUT, headers=client.csrf_headers).status_code == 204
    assert client.get(DEVICES).status_code == 401

    # Replaying the pre-logout cookie must not work: the row is gone, so
    # revocation is real rather than client-side advice.
    client.cookies.set(SESSION_COOKIE_NAME, stolen)
    assert client.get(DEVICES).status_code == 401


def test_only_the_tokens_digest_is_persisted(client):
    raw_session = client.cookies[SESSION_COOKIE_NAME]
    raw_csrf = client.cookies[CSRF_COOKIE_NAME]
    db = SessionLocal()
    try:
        row = _session_row(db, client)
        stored = f"{row.token_hash} {row.csrf_hash} {row.id} {row.username}"
    finally:
        db.close()
    assert raw_session not in stored
    assert raw_csrf not in stored
    assert auth.hash_token(raw_session) in stored


def _session_row(db, client):
    """The AdminSession row backing this client's cookie."""
    token_hash = auth.hash_token(client.cookies[SESSION_COOKIE_NAME])
    return db.query(AdminSession).filter(AdminSession.token_hash == token_hash).one()


def test_expired_session_is_rejected_and_purged(client):
    token_hash = auth.hash_token(client.cookies[SESSION_COOKIE_NAME])
    db = SessionLocal()
    try:
        _session_row(db, client).expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    assert client.get(DEVICES).status_code == 401

    db = SessionLocal()
    try:
        remaining = (
            db.query(AdminSession).filter(AdminSession.token_hash == token_hash).count()
        )
    finally:
        db.close()
    assert remaining == 0


def test_idle_session_times_out_before_the_absolute_ttl(client, monkeypatch):
    monkeypatch.setattr(settings, "session_idle_timeout_seconds", 60)
    db = SessionLocal()
    try:
        row = _session_row(db, client)
        row.last_seen_at = datetime.now(UTC) - timedelta(seconds=120)
        db.commit()
        assert row.expires_at > datetime.now(UTC)  # absolute TTL has not elapsed
    finally:
        db.close()

    assert client.get(DEVICES).status_code == 401


def test_logging_in_again_issues_a_distinct_session(anon_client):
    first = login(anon_client)
    first_cookie = anon_client.cookies[SESSION_COOKIE_NAME]
    anon_client.cookies.clear()
    second = login(anon_client)
    assert anon_client.cookies[SESSION_COOKIE_NAME] != first_cookie
    assert first != second


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


UNSAFE_CALLS = [
    ("post", DEVICES, {"hostname": "csrf-host", "ip": [], "roles": [], "ports": []}),
    ("put", f"{DEVICES}/abc", {"hostname": "csrf-host", "ip": [], "roles": [], "ports": []}),
    ("patch", f"{DEVICES}/abc", {"hostname": "csrf-host"}),
    ("delete", f"{DEVICES}/abc", None),
]


@pytest.mark.parametrize(("method", "path", "body"), UNSAFE_CALLS)
def test_unsafe_methods_require_the_csrf_header(client, method, path, body):
    kwargs = {"json": body} if body is not None else {}
    assert getattr(client, method)(path, **kwargs).status_code == 403


def test_scan_requires_the_csrf_header(client, monkeypatch):
    # Scans are refused without an authorized scope (M08); authorize the
    # TEST-NET-1 documentation range so this test isolates CSRF behaviour.
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "192.0.2.0/24")
    assert client.post(PING_SWEEP).status_code == 403
    assert client.post(PING_SWEEP, headers=client.csrf_headers).status_code == 200


def test_a_wrong_csrf_token_is_rejected(client):
    bad = {"X-CSRF-Token": "attacker-chosen-value"}
    assert client.post(DEVICES, json={"hostname": "x"}, headers=bad).status_code == 403


def test_another_sessions_csrf_token_is_rejected(client, second_client):
    """A valid-but-foreign CSRF token must not satisfy this session."""
    other = login(second_client)
    assert (
        client.post(DEVICES, json={"hostname": "x"}, headers=other).status_code == 403
    )


def test_safe_methods_do_not_require_a_csrf_header(client):
    assert client.get(DEVICES).status_code == 200


def test_logout_is_csrf_protected(client):
    assert client.post(LOGOUT).status_code == 403
    assert client.get(DEVICES).status_code == 200  # still signed in


# ---------------------------------------------------------------------------
# Password hashing and production configuration
# ---------------------------------------------------------------------------


def test_hash_password_round_trips_and_salts():
    first = auth.hash_password("a-long-enough-password", iterations=1_000)
    second = auth.hash_password("a-long-enough-password", iterations=1_000)
    assert first != second  # distinct salts
    assert auth.verify_password("a-long-enough-password", first)
    assert not auth.verify_password("a-long-enough-passworD", first)


def test_short_passwords_are_refused():
    with pytest.raises(auth.PasswordPolicyError):
        auth.hash_password("short")


@pytest.mark.parametrize(
    "verifier",
    ["", "not-a-hash", "pbkdf2_sha256$0$c2FsdA==$ZGlnZXN0", "md5$1$a$b", "pbkdf2_sha256$1$$"],
)
def test_malformed_verifiers_never_authenticate(verifier):
    assert not auth.verify_password("any-password-at-all", verifier)


def test_production_without_a_verifier_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(settings, "admin_password_hash", None)
    with pytest.raises(auth.AuthConfigurationError):
        auth.validate_admin_configuration()


def test_production_rejects_a_weak_work_factor(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(
        settings, "admin_password_hash", auth.hash_password("a-long-password", iterations=10)
    )
    with pytest.raises(auth.AuthConfigurationError):
        auth.validate_admin_configuration()


def test_production_rejects_a_malformed_verifier(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(settings, "admin_password_hash", "garbage")
    with pytest.raises(auth.AuthConfigurationError):
        auth.validate_admin_configuration()


def test_production_accepts_a_strong_verifier(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(
        settings,
        "admin_password_hash",
        auth.hash_password("a-long-password", iterations=auth.MIN_PRODUCTION_ITERATIONS),
    )
    auth.validate_admin_configuration()  # must not raise


def test_dev_without_a_verifier_is_allowed_to_start(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "dev")
    monkeypatch.setattr(settings, "admin_password_hash", None)
    auth.validate_admin_configuration()  # must not raise


@pytest.mark.parametrize(
    ("app_env", "expected"),
    [("dev", False), ("test", False), ("local", False), ("prod", True), ("staging", True)],
)
def test_unknown_environments_are_treated_as_production(monkeypatch, app_env, expected):
    monkeypatch.setattr(settings, "app_env", app_env)
    assert settings.is_production is expected


def test_cookie_secure_defaults_to_on_in_production(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(settings, "session_cookie_secure_raw", None)
    assert settings.session_cookie_secure is True

    monkeypatch.setattr(settings, "app_env", "dev")
    assert settings.session_cookie_secure is False
