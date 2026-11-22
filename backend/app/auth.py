"""Single-operator administrator authentication (M03, issue #6).

Design notes
------------
* The raw admin password is never stored anywhere. Only a PBKDF2-HMAC-SHA256
  verifier string lives in the environment, and only its *hash* is ever
  compared -- in constant time.
* Sessions are server-side rows, so logout and expiry genuinely revoke
  access instead of merely asking the client to forget a token. Only the
  SHA-256 digests of the session and CSRF tokens are persisted, so a
  database leak cannot be replayed as a live session.
* Production fails closed: with no configured verifier the application
  refuses to start rather than silently serving an unauthenticated API.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from . import models
from .config import settings

logger = logging.getLogger(__name__)

PBKDF2_ALGORITHM = "pbkdf2_sha256"
# OWASP's 2023 floor for PBKDF2-HMAC-SHA256.
DEFAULT_ITERATIONS = 600_000
# Production refuses to honour a verifier generated with a weaker work factor.
MIN_PRODUCTION_ITERATIONS = 100_000
SALT_BYTES = 16
TOKEN_BYTES = 32

MIN_PASSWORD_LENGTH = 12

# Brute-force throttle for the single admin account. Deliberately in-memory:
# it is per-process state that must not survive as durable, attacker-visible
# data, and a restart-based reset still costs an attacker the restart.
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_failed_attempts: dict[str, tuple[int, float]] = {}


class PasswordPolicyError(ValueError):
    """Raised when a candidate password is too weak to be hashed."""


class AuthConfigurationError(RuntimeError):
    """Raised when production is missing or has an unusable admin verifier."""


@dataclass(frozen=True)
class AuthenticatedSession:
    """The validated identity attached to a request."""

    session_id: str
    username: str
    expires_at: datetime
    csrf_hash: str


# --------------------------------------------------------------------------
# Password hashing
# --------------------------------------------------------------------------


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Return a ``pbkdf2_sha256$iterations$salt$digest`` verifier string."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Admin password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    if iterations < 1:
        raise ValueError("iterations must be positive")
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{PBKDF2_ALGORITHM}${iterations}${_b64encode(salt)}${_b64encode(digest)}"


def _parse_verifier(verifier: str) -> tuple[int, bytes, bytes]:
    """Split a verifier string, raising ``ValueError`` if it is malformed."""
    parts = verifier.split("$")
    if len(parts) != 4 or parts[0] != PBKDF2_ALGORITHM:
        raise ValueError("Unsupported admin password hash format")
    iterations = int(parts[1])
    if iterations < 1:
        raise ValueError("Admin password hash has a non-positive iteration count")
    salt = base64.b64decode(parts[2], validate=True)
    digest = base64.b64decode(parts[3], validate=True)
    if not salt or not digest:
        raise ValueError("Admin password hash is missing its salt or digest")
    return iterations, salt, digest


def verify_password(password: str, verifier: str) -> bool:
    """Constant-time check of ``password`` against a verifier string."""
    try:
        iterations, salt, expected = _parse_verifier(verifier)
    except (ValueError, TypeError):
        logger.warning("Admin password hash is malformed; refusing authentication")
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def validate_admin_configuration() -> None:
    """Fail closed when production has no usable admin verifier.

    Called at import time from ``app.main`` so a misconfigured production
    deployment stops at startup instead of serving an open API.
    """
    if not settings.is_production:
        if not settings.admin_password_hash:
            logger.warning(
                "APP_ENV=%s with no ADMIN_PASSWORD_HASH: login is disabled and every "
                "protected route will return 401. This is permitted only outside "
                "production.",
                settings.app_env,
            )
        return

    if not settings.admin_password_hash:
        raise AuthConfigurationError(
            "ADMIN_PASSWORD_HASH is required when APP_ENV is a production environment. "
            "Generate one with: python -m app.admin_password"
        )
    try:
        iterations, _, _ = _parse_verifier(settings.admin_password_hash)
    except (ValueError, TypeError) as exc:
        raise AuthConfigurationError(f"ADMIN_PASSWORD_HASH is not usable: {exc}") from None
    if iterations < MIN_PRODUCTION_ITERATIONS:
        raise AuthConfigurationError(
            f"ADMIN_PASSWORD_HASH uses {iterations} PBKDF2 iterations; production "
            f"requires at least {MIN_PRODUCTION_ITERATIONS}"
        )
    if not settings.session_cookie_secure:
        logger.warning(
            "SESSION_COOKIE_SECURE is disabled in a production environment. Session "
            "cookies will be sent over plain HTTP; only do this on a trusted "
            "loopback/LAN origin."
        )


# --------------------------------------------------------------------------
# Brute-force throttling
# --------------------------------------------------------------------------


def _lockout_remaining(key: str) -> int:
    entry = _failed_attempts.get(key)
    if not entry:
        return 0
    count, last_failure = entry
    if count < MAX_FAILED_ATTEMPTS:
        return 0
    remaining = int(last_failure + LOCKOUT_SECONDS - time.monotonic())
    if remaining <= 0:
        _failed_attempts.pop(key, None)
        return 0
    return remaining


def record_failed_attempt(key: str) -> None:
    count, _ = _failed_attempts.get(key, (0, 0.0))
    _failed_attempts[key] = (count + 1, time.monotonic())


def reset_failed_attempts(key: str) -> None:
    _failed_attempts.pop(key, None)


def clear_login_throttle() -> None:
    """Test/operational helper: forget every recorded failure."""
    _failed_attempts.clear()


# --------------------------------------------------------------------------
# Credential check
# --------------------------------------------------------------------------

# A syntactically valid verifier over an unguessable secret. Used to keep the
# "unknown user" and "no verifier configured" paths as expensive as a real
# check, so response timing does not reveal which case was hit.
_DUMMY_VERIFIER = hash_password(secrets.token_urlsafe(32), iterations=1_000)


def authenticate(username: str, password: str) -> bool:
    """Verify operator credentials, with user-enumeration-resistant timing."""
    verifier = settings.admin_password_hash
    expected_user = settings.admin_username
    user_ok = hmac.compare_digest(username.encode("utf-8"), expected_user.encode("utf-8"))
    # Always run a PBKDF2 round, even for an unknown user or unset verifier.
    password_ok = verify_password(password, verifier or _DUMMY_VERIFIER)
    return bool(verifier) and user_ok and password_ok


# --------------------------------------------------------------------------
# Session lifecycle
# --------------------------------------------------------------------------


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IssuedSession:
    session_token: str
    csrf_token: str
    expires_at: datetime


def create_session(db: Session, username: str) -> IssuedSession:
    """Issue a new server-side session and return its raw (never-stored) tokens."""
    now = datetime.now(UTC)
    session_token = secrets.token_urlsafe(TOKEN_BYTES)
    csrf_token = secrets.token_urlsafe(TOKEN_BYTES)
    expires_at = now + timedelta(seconds=settings.session_ttl_seconds)

    db.add(
        models.AdminSession(
            id=secrets.token_hex(16),
            token_hash=hash_token(session_token),
            csrf_hash=hash_token(csrf_token),
            username=username,
            created_at=now,
            last_seen_at=now,
            expires_at=expires_at,
        )
    )
    _purge_expired(db, now)
    db.commit()
    return IssuedSession(
        session_token=session_token, csrf_token=csrf_token, expires_at=expires_at
    )


def _purge_expired(db: Session, now: datetime) -> None:
    """Drop rows that can no longer authenticate anything."""
    idle_cutoff = now - timedelta(seconds=settings.session_idle_timeout_seconds)
    (
        db.query(models.AdminSession)
        .filter(
            (models.AdminSession.expires_at <= now)
            | (models.AdminSession.last_seen_at <= idle_cutoff)
        )
        .delete(synchronize_session=False)
    )


# Avoid a write on every single request while still keeping the idle timeout
# meaningful.
_LAST_SEEN_WRITE_INTERVAL_SECONDS = 60


def resolve_session(db: Session, session_token: str | None) -> AuthenticatedSession | None:
    """Return the live session for a raw token, or ``None`` if unusable."""
    if not session_token:
        return None
    row = (
        db.query(models.AdminSession)
        .filter(models.AdminSession.token_hash == hash_token(session_token))
        .first()
    )
    if row is None:
        return None

    now = datetime.now(UTC)
    idle_cutoff = now - timedelta(seconds=settings.session_idle_timeout_seconds)
    if row.expires_at <= now or row.last_seen_at <= idle_cutoff:
        # Expired or idled out: revoke rather than leave a stale row behind.
        db.delete(row)
        db.commit()
        return None

    resolved = AuthenticatedSession(
        session_id=row.id,
        username=row.username,
        expires_at=row.expires_at,
        csrf_hash=row.csrf_hash,
    )
    if (now - row.last_seen_at).total_seconds() >= _LAST_SEEN_WRITE_INTERVAL_SECONDS:
        row.last_seen_at = now
        db.commit()
    return resolved


def revoke_session(db: Session, session_token: str | None) -> bool:
    """Delete the session row for a raw token. Returns True if one existed."""
    if not session_token:
        return False
    deleted = (
        db.query(models.AdminSession)
        .filter(models.AdminSession.token_hash == hash_token(session_token))
        .delete(synchronize_session=False)
    )
    db.commit()
    return bool(deleted)


def login_lockout_remaining(username: str) -> int:
    return _lockout_remaining(username)
