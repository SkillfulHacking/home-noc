"""M07 (#10): Compose hardening, bootstrap, SQLite persistence and recovery.

Everything here uses temporary files/databases and throwaway keys. No test
touches a real ``.env``, a real database or any network.
"""
from __future__ import annotations

import base64
import errno
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import types
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from dotenv import dotenv_values
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session

from alembic import command
from app import admin_password, auth, crypto, dbtool, key_binding, models
from app.config import settings

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"
COMPOSE = REPO / "docker-compose.yml"
COMPOSE_DEV = REPO / "docker-compose.dev.yml"
PLAINTEXT_SECRET = b"unifi-token-plaintext-canary"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _service_block(name: str, path: Path = COMPOSE) -> str:
    """Return the comment-stripped text of one service in a Compose file."""
    block: list[str] = []
    inside = False
    in_services = False
    for line in path.read_text().splitlines():
        if line.startswith("services:"):
            in_services = True
            continue
        if not in_services:
            continue
        if line and not line.startswith((" ", "#")):
            break  # next top-level key
        header = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if header:
            inside = header.group(1) == name
            continue
        if inside and not line.strip().startswith("#"):
            block.append(line)
    assert block, f"service {name!r} not found"
    return "\n".join(block)


def _compose_text() -> str:
    return "\n".join(
        ln for ln in COMPOSE.read_text().splitlines() if not ln.strip().startswith("#")
    )


def _alembic_config() -> Config:
    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND / "alembic"))
    return config


def _migrate(monkeypatch, db_file: Path, revision: str = "head") -> str:
    url = f"sqlite:///{db_file}"
    monkeypatch.setattr(settings, "db_url", url)
    command.upgrade(_alembic_config(), revision)
    return url


def _counts(db_file: Path) -> dict[str, int]:
    conn = sqlite3.connect(db_file)
    try:
        return {
            table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
            for table in (
                "devices",
                "device_identities",
                "device_observations",
                "admin_sessions",
                "connector_credentials",
                "credential_key_verifier",
            )
        }
    finally:
        conn.close()


def _populate(url: str, key: bytes) -> None:
    now = datetime.now(UTC)
    engine = sa.create_engine(url)
    with Session(engine) as db:
        device_id = str(uuid.uuid4())
        db.add(models.Device(id=device_id, hostname="nas", ip={"v": ["192.0.2.10"]}))
        db.flush()
        db.add(
            models.DeviceIdentity(
                id=str(uuid.uuid4()), device_id=device_id, source="mac", external_id="aa:bb"
            )
        )
        db.add(
            models.DeviceObservation(
                id=str(uuid.uuid4()),
                device_id=device_id,
                source="operator",
                observed_at=now,
                data={"hostname": "nas"},
            )
        )
        db.add(
            models.AdminSession(
                id=uuid.uuid4().hex,
                token_hash="a" * 64,
                csrf_hash="b" * 64,
                username="admin",
                created_at=now,
                last_seen_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        cred_id = str(uuid.uuid4())
        key_binding.bind_for_write(db, key)
        aad = crypto.build_aad(
            credential_id=cred_id, scope_key="connector:unifi", credential_type="unifi_api_token"
        )
        db.add(
            models.ConnectorCredential(
                id=cred_id,
                scope_key="connector:unifi",
                connector="unifi",
                credential_type="unifi_api_token",
                enc_version=crypto.FORMAT_VERSION,
                ciphertext=crypto.encrypt(PLAINTEXT_SECRET, aad=aad, key=key),
                meta={},
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    engine.dispose()


@pytest.fixture
def populated(tmp_path, monkeypatch):
    """A migrated, populated database plus the key that protects it."""
    db_file = tmp_path / "data" / "home_noc.db"
    db_file.parent.mkdir()
    url = _migrate(monkeypatch, db_file)
    key = crypto.load_key()  # the per-test key installed by conftest
    _populate(url, key)
    return types.SimpleNamespace(path=db_file, url=url, key=key)


def _other_key() -> SecretStr:
    return SecretStr(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))


# --------------------------------------------------------------------------
# Compose configuration
# --------------------------------------------------------------------------


def test_backend_port_is_not_published_by_default():
    backend = _service_block("backend")
    assert "ports:" not in backend
    assert re.search(r'expose:\s*\n\s*- "8000"', backend)
    # The only host publication in the base file is the frontend.
    assert _compose_text().count("ports:") == 1


def test_frontend_published_on_3000_and_waits_for_healthy_backend():
    frontend = _service_block("frontend")
    # Loopback-only unless the operator explicitly sets HOME_NOC_FRONTEND_BIND.
    assert '"${HOME_NOC_FRONTEND_BIND:-127.0.0.1:3000}:80"' in frontend
    assert re.search(r"depends_on:\s*\n\s*backend:\s*\n\s*condition: service_healthy", frontend)
    assert "healthcheck:" in frontend
    assert "healthcheck:" in _service_block("backend")


def test_dev_override_is_opt_in_loopback_and_backend_only():
    text = "\n".join(
        ln for ln in COMPOSE_DEV.read_text().splitlines() if not ln.strip().startswith("#")
    )
    assert "HOME_NOC_BACKEND_BIND:-127.0.0.1:8000" in text
    assert ":8000\"" in text
    assert "frontend" not in text
    # Never auto-loaded: Compose only merges docker-compose.override.yml itself.
    assert COMPOSE_DEV.name != "docker-compose.override.yml"
    assert not (REPO / "docker-compose.override.yml").exists()


def test_compose_has_no_privileged_or_host_access():
    text = _compose_text()
    for forbidden in (
        "privileged",
        "network_mode",
        "pid: host",
        "ipc: host",
        "NET_RAW",
        "NET_ADMIN",
        "SYS_ADMIN",
        "docker.sock",
        "devices:",
    ):
        assert forbidden not in text, forbidden
    backend = _service_block("backend")
    assert "cap_add" not in backend  # scanner capabilities stay disabled
    assert re.search(r"cap_drop:\s*\n\s*- ALL", backend)
    assert "no-new-privileges:true" in backend
    assert 'user: "10001"' in backend
    assert "read_only: true" in backend


def test_frontend_capabilities_are_the_minimal_nginx_set():
    frontend = _service_block("frontend")
    assert re.search(r"cap_drop:\s*\n\s*- ALL", frontend)
    added = re.search(r"cap_add:\n((?:\s+- \w+\n?)+)", frontend + "\n")
    assert added
    caps = set(re.findall(r"- (\w+)", added.group(1)))
    assert caps == {"CHOWN", "SETGID", "SETUID", "NET_BIND_SERVICE"}


def test_encryption_key_is_a_secret_mount_outside_the_data_volume():
    backend = _service_block("backend")
    assert "/run/secrets/home_noc_credential_key" in backend
    assert "- home_noc_credential_key" in backend
    assert "api_data:/data" in backend
    text = _compose_text()
    assert "file: \"${HOME_NOC_CREDENTIAL_KEY_FILE:-./secrets/credential_key}\"" in text
    # No key material or default password may sit in the Compose file.
    assert "CREDENTIAL_ENCRYPTION_KEY:" not in text
    assert "ADMIN_PASSWORD" not in text


def test_same_origin_nginx_proxy_is_preserved():
    nginx = (REPO / "frontend" / "nginx.conf").read_text()
    assert "proxy_pass http://backend:8000;" in nginx
    assert "Access-Control" not in nginx
    assert "CORS_ORIGINS" not in COMPOSE.read_text().replace("# No CORS_ORIGINS", "")


def _docker_compose_config(
    tmp_path: Path, *files: Path, extra_env: dict | None = None, cwd: Path = REPO
) -> dict:
    env_file = tmp_path / "test.env"
    env_file.write_text("APP_ENV=prod\n")
    key_file = tmp_path / "key"
    key_file.write_text("x\n")
    # Never inherit the developer's own project/bind settings: the defaults are
    # what is under test.
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"COMPOSE_PROJECT_NAME", "HOME_NOC_FRONTEND_BIND", "HOME_NOC_BACKEND_BIND"}
    }
    env.update(
        {
            "HOME_NOC_ENV_FILE": str(env_file),
            "HOME_NOC_CREDENTIAL_KEY_FILE": str(key_file),
            **(extra_env or {}),
        }
    )
    args = ["docker", "compose"]
    for f in files:
        args += ["-f", str(f)]
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [*args, "config", "--format", "json"],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not available")
def test_rendered_compose_config(tmp_path):
    config = _docker_compose_config(tmp_path, COMPOSE)
    backend, frontend = config["services"]["backend"], config["services"]["frontend"]
    assert "ports" not in backend
    # Safe default: plain HTTP is reachable from this machine only.
    assert [(p["host_ip"], p["published"]) for p in frontend["ports"]] == [("127.0.0.1", "3000")]
    assert backend["user"] == "10001"
    assert backend["cap_drop"] == ["ALL"]
    assert not backend.get("privileged")
    assert frontend["depends_on"]["backend"]["condition"] == "service_healthy"
    assert "container_name" not in backend and "container_name" not in frontend
    assert "image" not in backend  # Compose derives a project-scoped image name

    dev = _docker_compose_config(tmp_path, COMPOSE, COMPOSE_DEV)
    (port,) = dev["services"]["backend"]["ports"]
    assert port["host_ip"] == "127.0.0.1" and port["target"] == 8000


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not available")
def test_rendered_project_name_is_stable_and_overridable(tmp_path):
    # The same file in differently named checkout directories keeps one project
    # name (so one data volume), while COMPOSE_PROJECT_NAME still overrides it.
    for dirname in ("home-noc", "home-noc-m07", "Some Other Checkout"):
        checkout = tmp_path / dirname
        (checkout / "backend").mkdir(parents=True)
        (checkout / "frontend").mkdir()
        shutil.copy2(COMPOSE, checkout / "docker-compose.yml")
        config = _docker_compose_config(tmp_path, checkout / "docker-compose.yml", cwd=checkout)
        assert config["name"] == "home-noc", dirname
    override = _docker_compose_config(
        tmp_path, COMPOSE, extra_env={"COMPOSE_PROJECT_NAME": "home-noc-staging"}
    )
    assert override["name"] == "home-noc-staging"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not available")
def test_rendered_lan_exposure_requires_explicit_configuration(tmp_path):
    config = _docker_compose_config(
        tmp_path, COMPOSE, extra_env={"HOME_NOC_FRONTEND_BIND": "0.0.0.0:8443"}
    )
    (port,) = config["services"]["frontend"]["ports"]
    assert port["host_ip"] == "0.0.0.0" and port["published"] == "8443"  # noqa: S104


def test_compose_has_stable_project_name_and_no_fixed_names_or_shared_tags():
    lines = COMPOSE.read_text().splitlines()
    assert "name: home-noc" in lines  # top-level, unindented
    text = _compose_text()
    assert "container_name" not in text  # fixed names collide between projects
    for service in ("backend", "frontend"):
        block = _service_block(service)
        assert "container_name" not in block
        # A literal image tag (e.g. home-noc-api:latest) is shared and mutable
        # across dev/test/prod projects; Compose's <project>-<service> is not.
        assert not re.search(r"^\s*image:", block, re.MULTILINE), service
    dev = COMPOSE_DEV.read_text()
    assert "container_name" not in dev and "image:" not in dev


# --------------------------------------------------------------------------
# Image, entrypoint, non-root, migrations-once
# --------------------------------------------------------------------------


def test_backend_image_runs_as_non_root_uid_10001():
    dockerfile = (BACKEND / "Dockerfile").read_text()
    assert "useradd -r -u 10001 appuser" in dockerfile
    user_lines = [ln for ln in dockerfile.splitlines() if ln.startswith("USER ")]
    assert user_lines[-1] == "USER appuser"
    assert "chown -R appuser:appuser /data" in dockerfile
    # Nothing secret is baked into the image.
    for needle in ("ADMIN_PASSWORD_HASH", "CREDENTIAL_ENCRYPTION_KEY", "COPY .env"):
        assert needle not in dockerfile


def test_entrypoint_migrates_once_and_fails_clearly():
    script = (BACKEND / "entrypoint.sh").read_text()
    executable = [ln for ln in script.splitlines() if not ln.lstrip().startswith(("#", "echo"))]
    body = "\n".join(executable)
    assert body.count("upgrade head") == 1
    assert "set -eu" in script
    assert "umask 077" in script
    assert "migration failed" in script
    assert script.index("upgrade head") < script.index("exec python")
    assert "exec python -m uvicorn" in script
    assert "--workers 1" in script  # one process => one migration runner


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    "script", ["bootstrap.sh", "backup.sh", "restore.sh", "ci-restore-integration.sh"]
)
def test_operator_scripts_are_valid_bash(script):
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", "-n", str(REPO / "scripts" / script)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr


# --------------------------------------------------------------------------
# Bootstrap: secrets handling and configuration
# --------------------------------------------------------------------------


def test_bootstrap_script_safeguards():
    script = (REPO / "scripts" / "bootstrap.sh").read_text()
    assert "SESSION_COOKIE_SECURE=true" in script  # HTTPS is the default
    assert "--http) COOKIE_SECURE=false" in script  # relaxed only on explicit request
    assert "--network none" in script
    assert "--output /out/admin_hash" in script  # verifier via file, not argv/stdout
    assert 'if [ -e "$ENV_FILE" ]' in script  # never overwrites an env file
    assert "mv -n" in script
    assert "never regenerated" in script
    assert "chmod 700" in script and "chmod 444" in script
    assert "umask 077" in script
    # The password/key must never travel on a command line.
    assert not re.search(r"--password|ADMIN_PASSWORD=", script)
    assert "echo \"$(cat" not in script
    # Only the example file is read; no real env/secret is consumed.
    assert "cat backend/.env.example" in script


def test_env_example_has_no_defaults_or_secrets():
    example = (BACKEND / ".env.example").read_text()
    active = {
        ln.split("=", 1)[0]: ln.split("=", 1)[1]
        for ln in example.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#") and "=" in ln
    }
    assert "ADMIN_PASSWORD_HASH" not in active
    assert "ADMIN_PASSWORD" not in active
    assert "CREDENTIAL_ENCRYPTION_KEY" not in active
    assert "SESSION_COOKIE_SECURE" not in active  # relaxed only via explicit bootstrap
    assert active["AUTO_CREATE_TABLES"] == "0"
    assert not re.search(r"pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$", example)


def test_gitignore_covers_generated_secrets():
    ignored = (REPO / ".gitignore").read_text().splitlines()
    for entry in ("/secrets/", "/backups/", "backend/.env"):
        assert entry in ignored


def test_admin_password_output_file_round_trip(tmp_path, monkeypatch):
    """The generated line is quoted, private, verifiable and Compose-safe."""
    password = "Tr0ub4dor&3-horse-staple"  # noqa: S105 - throwaway test value
    monkeypatch.setattr(admin_password.sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(admin_password.getpass, "getpass", lambda _prompt: password)
    out = tmp_path / "admin_hash"

    assert admin_password.main(["--output", str(out)]) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    content = out.read_text()
    assert re.fullmatch(
        r"ADMIN_PASSWORD_HASH='pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+'\n",
        content,
    )
    assert password not in content

    # dotenv (and Compose, which requires single quotes) keep '$' intact.
    verifier = dotenv_values(out)["ADMIN_PASSWORD_HASH"]
    assert verifier.count("$") == 3
    assert auth.verify_password(password, verifier)
    assert not auth.verify_password("wrong password value", verifier)

    # Exclusive create: an existing file is never overwritten.
    out.write_text("keep")
    assert admin_password.main(["--output", str(out)]) == 1
    assert out.read_text() == "keep"


def test_admin_password_rejects_weak_password_and_pipes(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(admin_password.sys, "stdin", types.SimpleNamespace(isatty=lambda: False))
    assert admin_password.main(["--output", str(tmp_path / "x")]) == 2
    monkeypatch.setattr(admin_password.sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(admin_password.getpass, "getpass", lambda _prompt: "short")
    assert admin_password.main(["--output", str(tmp_path / "x")]) == 1
    assert not (tmp_path / "x").exists()
    assert "short" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "app_env,verifier",
    [
        ("prod", None),  # missing
        ("prod", ""),
        ("prod", "plaintext-password"),  # not a verifier
        ("prod", "pbkdf2_sha256$1000$AAAA$AAAA"),  # work factor below production floor
        ("production", "pbkdf2_sha256$600000$not base64$@@@@"),
    ],
)
def test_production_fails_closed_on_missing_or_invalid_admin_config(
    monkeypatch, app_env, verifier
):
    monkeypatch.setattr(settings, "app_env", app_env)
    monkeypatch.setattr(settings, "admin_password_hash", verifier)
    with pytest.raises(auth.AuthConfigurationError):
        auth.validate_admin_configuration()


def test_production_accepts_a_valid_bootstrap_verifier(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(
        settings, "admin_password_hash", auth.hash_password("a-long-enough-password")
    )
    auth.validate_admin_configuration()  # does not raise


def test_fresh_install_serves_health_and_requires_login(tmp_path, monkeypatch):
    """A freshly migrated empty database is healthy; the API stays closed."""
    from app import main

    url = _migrate(monkeypatch, tmp_path / "fresh.db")
    engine = sa.create_engine(url)
    monkeypatch.setattr(main, "engine", engine)
    client = TestClient(main.app)
    assert client.get("/health").json() == {"ok": True, "app": "home-noc"}
    assert client.get("/api/v1/devices").status_code == 401
    engine.dispose()


# --------------------------------------------------------------------------
# Health checks
# --------------------------------------------------------------------------


def test_health_reports_503_when_schema_is_missing(tmp_path, monkeypatch):
    from app import main

    db_file = tmp_path / "unmigrated.db"
    engine = sa.create_engine(f"sqlite:///{db_file}")
    monkeypatch.setattr(main, "engine", engine)
    response = TestClient(main.app).get("/health")
    assert response.status_code == 503
    assert response.json() == {"ok": False, "detail": "database schema is not initialized"}
    engine.dispose()


def test_health_reports_503_without_leaking_paths_when_db_unreachable(tmp_path, monkeypatch):
    from app import main

    missing_dir = tmp_path / "does-not-exist" / "x.db"
    engine = sa.create_engine(f"sqlite:///{missing_dir}")
    monkeypatch.setattr(main, "engine", engine)
    response = TestClient(main.app).get("/health")
    assert response.status_code == 503
    assert response.json() == {"ok": False, "detail": "database unavailable"}
    assert str(tmp_path) not in response.text
    engine.dispose()


# --------------------------------------------------------------------------
# Migrations 0004 / 0005
# --------------------------------------------------------------------------


def test_migrations_0004_and_0005_apply_in_order_and_are_idempotent(tmp_path, monkeypatch):
    db_file = tmp_path / "m.db"
    _migrate(monkeypatch, db_file, "0003_admin_sessions")
    engine = sa.create_engine(f"sqlite:///{db_file}")
    tables = set(sa.inspect(engine).get_table_names())
    assert "connector_credentials" not in tables and "credential_key_verifier" not in tables

    command.upgrade(_alembic_config(), "0004_connector_credentials")
    tables = set(sa.inspect(engine).get_table_names())
    assert "connector_credentials" in tables and "credential_key_verifier" not in tables

    command.upgrade(_alembic_config(), "0005_credential_key_verifier")
    inspector = sa.inspect(engine)
    assert "credential_key_verifier" in inspector.get_table_names()
    assert {c["name"] for c in inspector.get_columns("credential_key_verifier")} == {
        "id", "version", "salt", "verifier", "created_at",
    }
    # Re-running head (every container start) is a no-op.
    command.upgrade(_alembic_config(), "head")
    command.upgrade(_alembic_config(), "head")
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM alembic_version")).scalar_one() == 1
    engine.dispose()


def test_downgrading_0005_keeps_credentials(populated):
    engine = sa.create_engine(populated.url)
    before = _counts(populated.path)
    assert before["credential_key_verifier"] == 1 and before["connector_credentials"] == 1
    command.downgrade(_alembic_config(), "0004_connector_credentials")
    inspector = sa.inspect(engine)
    assert "credential_key_verifier" not in inspector.get_table_names()
    assert _counts_without_verifier(populated.path)["connector_credentials"] == 1
    command.upgrade(_alembic_config(), "head")
    engine.dispose()


def _counts_without_verifier(db_file: Path) -> dict[str, int]:
    conn = sqlite3.connect(db_file)
    try:
        return {
            "connector_credentials": conn.execute(
                "SELECT count(*) FROM connector_credentials"
            ).fetchone()[0]
        }
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Restart persistence
# --------------------------------------------------------------------------


def test_data_survives_restart_and_repeat_migration(populated):
    before = _counts(populated.path)
    assert before == {
        "devices": 1,
        "device_identities": 1,
        "device_observations": 1,
        "admin_sessions": 1,
        "connector_credentials": 1,
        "credential_key_verifier": 1,
    }
    # "Restart": the container runs `alembic upgrade head` again on a new process.
    command.upgrade(_alembic_config(), "head")
    assert _counts(populated.path) == before

    engine = sa.create_engine(populated.url)
    with Session(engine) as db:
        key_binding.check_usable(db, populated.key)  # same key still accepted
        row = db.query(models.ConnectorCredential).one()
        aad = crypto.build_aad(
            credential_id=row.id, scope_key=row.scope_key, credential_type=row.credential_type
        )
        assert crypto.decrypt(row.ciphertext, aad=aad, key=populated.key) == PLAINTEXT_SECRET
    engine.dispose()


def test_wrong_key_is_rejected_after_restart(populated):
    engine = sa.create_engine(populated.url)
    wrong = base64.urlsafe_b64decode(_other_key().get_secret_value())
    with Session(engine) as db, pytest.raises(key_binding.CredentialKeyMismatchError):
        key_binding.check_usable(db, wrong)
    engine.dispose()
    assert _counts(populated.path)["credential_key_verifier"] == 1  # never replaced


# --------------------------------------------------------------------------
# Backup
# --------------------------------------------------------------------------


def test_backup_is_complete_private_and_excludes_the_key(populated, tmp_path):
    out = tmp_path / "backups" / "b.sqlite3"
    out.parent.mkdir()
    dbtool.create_backup(populated.path, out)

    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert _counts(out) == _counts(populated.path)
    raw = out.read_bytes()
    assert raw.startswith(dbtool.SQLITE_HEADER)
    assert populated.key not in raw
    assert base64.urlsafe_b64encode(populated.key) not in raw
    assert PLAINTEXT_SECRET not in raw  # credentials stay encrypted at rest
    assert not list(out.parent.glob("*-journal"))


def test_backup_uses_a_consistent_snapshot_while_the_db_is_open(populated, tmp_path):
    """A writer holding the database open does not corrupt the snapshot."""
    writer = sqlite3.connect(populated.path)
    try:
        writer.execute("INSERT INTO devices (id, hostname) VALUES ('live-1', 'during-backup')")
        writer.commit()
        out = tmp_path / "live.sqlite3"
        dbtool.create_backup(populated.path, out)
    finally:
        writer.close()
    assert _counts(out)["devices"] == 2
    conn = sqlite3.connect(out)
    assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    conn.close()


def test_backup_never_overwrites_and_cleans_up_on_failure(populated, tmp_path):
    existing = tmp_path / "existing.sqlite3"
    existing.write_bytes(b"precious")
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.create_backup(populated.path, existing)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert existing.read_bytes() == b"precious"

    with pytest.raises(dbtool.DbToolError):
        dbtool.create_backup(tmp_path / "missing.db", tmp_path / "new.sqlite3")
    assert not (tmp_path / "new.sqlite3").exists()


def test_backup_cli_writes_file_and_logs_no_secrets(populated, tmp_path, capsys):
    out = tmp_path / "cli.sqlite3"
    assert dbtool.main(["backup", "--output", str(out)]) == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert out.exists()
    assert base64.urlsafe_b64encode(populated.key).decode() not in combined
    assert PLAINTEXT_SECRET.decode() not in combined


# --------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------


def _backup_bytes(populated, tmp_path) -> bytes:
    out = tmp_path / "src.sqlite3"
    dbtool.create_backup(populated.path, out)
    return out.read_bytes()


def test_restore_into_empty_volume_round_trips(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    target_dir = tmp_path / "fresh-volume"
    target_dir.mkdir()
    target = target_dir / "home_noc.db"

    moved = dbtool.restore_database(io.BytesIO(data), target)

    assert moved is None
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert _counts(target) == _counts(populated.path)
    assert not [p for p in target_dir.iterdir() if p.name != target.name]  # no temp leftovers
    conn = sqlite3.connect(target)
    assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    conn.close()


def test_restore_refuses_to_overwrite_an_existing_database(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    before = populated.path.read_bytes()
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(io.BytesIO(data), populated.path)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert populated.path.read_bytes() == before
    assert not list(populated.path.parent.glob(".restore-*"))


def test_restore_refuses_when_only_a_stale_journal_exists(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    target_dir = tmp_path / "stale"
    target_dir.mkdir()
    (target_dir / "home_noc.db-wal").write_bytes(b"stale")
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(io.BytesIO(data), target_dir / "home_noc.db")
    assert exc.value.code == dbtool.EXIT_REFUSED


def test_restore_replace_moves_the_old_database_aside_instead_of_deleting(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    sqlite3.connect(populated.path).execute("DELETE FROM devices").connection.commit()
    (populated.path.parent / "home_noc.db-journal").write_bytes(b"old-journal")
    damaged = populated.path.read_bytes()

    moved = dbtool.restore_database(io.BytesIO(data), populated.path, replace=True)

    assert moved is not None and moved.read_bytes() == damaged
    assert Path(f"{moved}-journal").read_bytes() == b"old-journal"
    assert not (populated.path.parent / "home_noc.db-journal").exists()
    assert _counts(populated.path)["devices"] == 1  # the backup's content
    assert "pre-restore" in moved.name


def test_restore_rejects_a_backup_for_a_different_key(populated, tmp_path, monkeypatch):
    data = _backup_bytes(populated, tmp_path)
    monkeypatch.setattr(settings, "credential_encryption_key", _other_key())
    target = tmp_path / "other" / "home_noc.db"
    target.parent.mkdir()
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(io.BytesIO(data), target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert "does not match" in str(exc.value)
    assert not list(target.parent.iterdir())  # nothing installed, no temp files


def test_restore_requires_a_key_unless_explicitly_skipped(populated, tmp_path, monkeypatch):
    data = _backup_bytes(populated, tmp_path)
    monkeypatch.setattr(settings, "credential_encryption_key", None)
    target = tmp_path / "nokey" / "home_noc.db"
    target.parent.mkdir()
    with pytest.raises(dbtool.DbToolError):
        dbtool.restore_database(io.BytesIO(data), target)
    assert not list(target.parent.iterdir())
    dbtool.restore_database(io.BytesIO(data), target, check_key=False)
    assert target.exists()


@pytest.mark.parametrize(
    "payload",
    [b"", b"not a database at all", dbtool.SQLITE_HEADER + b"\x00" * 200],
)
def test_restore_rejects_invalid_input_without_side_effects(tmp_path, payload):
    target = tmp_path / "v" / "home_noc.db"
    target.parent.mkdir()
    with pytest.raises(dbtool.DbToolError):
        dbtool.restore_database(io.BytesIO(payload), target)
    assert not list(target.parent.iterdir())


def test_restore_rejects_a_foreign_sqlite_database(tmp_path):
    foreign = tmp_path / "foreign.db"
    conn = sqlite3.connect(foreign)
    conn.execute("CREATE TABLE unrelated (x)")
    conn.commit()
    conn.close()
    target = tmp_path / "v" / "home_noc.db"
    target.parent.mkdir()
    with pytest.raises(dbtool.DbToolError, match="not a Home-NOC database"):
        dbtool.restore_database(io.BytesIO(foreign.read_bytes()), target, check_key=False)
    assert not list(target.parent.iterdir())


def test_restore_enforces_a_size_limit(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    target = tmp_path / "v" / "home_noc.db"
    target.parent.mkdir()
    with pytest.raises(dbtool.DbToolError, match="maximum"):
        dbtool.restore_database(io.BytesIO(data), target, max_bytes=100)
    assert not list(target.parent.iterdir())


def test_restored_database_boots_with_the_original_key_only(populated, tmp_path, monkeypatch):
    """Database + externally stored key recover together; migration is a no-op."""
    data = _backup_bytes(populated, tmp_path)
    target = tmp_path / "recovered" / "home_noc.db"
    target.parent.mkdir()
    dbtool.restore_database(io.BytesIO(data), target)

    url = _migrate(monkeypatch, target)  # what the entrypoint does on start
    engine = sa.create_engine(url)
    with Session(engine) as db:
        key_binding.check_usable(db, populated.key)
        wrong = base64.urlsafe_b64decode(_other_key().get_secret_value())
        with pytest.raises(key_binding.CredentialKeyMismatchError):
            key_binding.check_usable(db, wrong)
    engine.dispose()
    assert _counts(target) == _counts(populated.path)


# --------------------------------------------------------------------------
# Permissions and CLI plumbing
# --------------------------------------------------------------------------


def test_harden_restricts_database_files(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_file = data_dir / "home_noc.db"
    for name in ("home_noc.db", "home_noc.db-journal"):
        (data_dir / name).write_bytes(b"x")
        os.chmod(data_dir / name, 0o644)
    dbtool.harden_permissions(db_file)
    assert stat.S_IMODE(db_file.stat().st_mode) == 0o600
    assert stat.S_IMODE((data_dir / "home_noc.db-journal").stat().st_mode) == 0o600
    assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700


def test_database_path_rejects_unsupported_urls():
    with pytest.raises(dbtool.DbToolError):
        dbtool.database_path("sqlite:///:memory:")
    with pytest.raises(dbtool.DbToolError):
        dbtool.database_path("postgresql://u@h/db")
    assert dbtool.database_path("sqlite:////data/home_noc.db") == Path("/data/home_noc.db")


def test_dbtool_module_runs_as_a_cli(populated, tmp_path):
    """`python -m app.dbtool backup` works end to end in a subprocess."""
    out = tmp_path / "sub.sqlite3"
    env = {
        **os.environ,
        "DB_URL": populated.url,
        "APP_ENV": "test",
        "PYTHONPATH": str(BACKEND),
    }
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "app.dbtool", "backup", "--output", str(out)],
        # cwd outside the repo so no local ``.env`` can be picked up.
        cwd=tmp_path, env=env, capture_output=True, check=False, timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert _counts(out) == _counts(populated.path)
    assert result.stdout == b""  # stdout is reserved for streamed backups


# --------------------------------------------------------------------------
# B2: no-clobber restore installation, races, symlinks, rollback
# --------------------------------------------------------------------------


class _RacingStream:
    """File-like upload that fires ``on_midstream`` between two reads of the data."""

    def __init__(self, data: bytes, on_midstream) -> None:
        half = len(data) // 2
        self._parts = [data[:half], data[half:], b""]
        self._on_midstream = on_midstream
        self._reads = 0

    def read(self, _size: int = -1) -> bytes:
        self._reads += 1
        if self._reads == 2:
            self._on_midstream()
        return self._parts.pop(0) if self._parts else b""


def _volume(tmp_path: Path, name: str = "vol") -> Path:
    directory = tmp_path / name
    directory.mkdir()
    return directory / "home_noc.db"


def _names(directory: Path) -> set[str]:
    return {p.name for p in directory.iterdir()}


def test_restore_never_clobbers_a_database_created_mid_stream(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)

    def appear() -> None:
        target.write_bytes(b"created-by-someone-else")

    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(_RacingStream(data, appear), target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert target.read_bytes() == b"created-by-someone-else"
    assert _names(target.parent) == {target.name}  # no candidate/temp leftovers


def test_restore_link_step_is_the_race_proof_guard(populated, tmp_path, monkeypatch):
    """Even if a database appears AFTER the last existence check, link(2) refuses."""
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)
    real = dbtool._existing_family
    calls: list[int] = []

    def racy(path: Path):
        result = real(path)
        calls.append(1)
        if len(calls) == 2:  # the re-check after validation; the file lands right after it
            path.write_bytes(b"late-arrival")
        return result

    monkeypatch.setattr(dbtool, "_existing_family", racy)
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(io.BytesIO(data), target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert target.read_bytes() == b"late-arrival"
    assert _names(target.parent) == {target.name}


def test_restore_removes_only_its_own_link_when_a_journal_appears_late(
    populated, tmp_path, monkeypatch
):
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)
    wal = Path(f"{target}-wal")
    real = dbtool._existing_family
    calls: list[int] = []

    def racy(path: Path):
        result = real(path)
        calls.append(1)
        if len(calls) == 2:
            wal.write_bytes(b"foreign-wal")
        return result

    monkeypatch.setattr(dbtool, "_existing_family", racy)
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(io.BytesIO(data), target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert not os.path.lexists(target)  # the link this call made is withdrawn
    assert wal.read_bytes() == b"foreign-wal"  # the foreign file is untouched
    assert _names(target.parent) == {wal.name}


def test_restore_refuses_when_a_journal_appears_mid_stream(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)
    wal = Path(f"{target}-wal")
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(_RacingStream(data, lambda: wal.write_bytes(b"w")), target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert not os.path.lexists(target)
    assert wal.read_bytes() == b"w"


@pytest.mark.parametrize("when", ["before", "mid-stream"])
def test_restore_treats_a_dangling_symlink_as_an_existing_database(populated, tmp_path, when):
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)
    ghost = target.parent / "ghost-target.db"  # never exists
    if when == "before":
        target.symlink_to(ghost)
        stream = io.BytesIO(data)
    else:
        stream = _RacingStream(data, lambda: target.symlink_to(ghost))

    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(stream, target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert target.is_symlink() and os.readlink(target) == str(ghost)
    assert not ghost.exists()  # nothing was written through the symlink
    assert _names(target.parent) == {target.name}


def test_restore_never_writes_through_a_symlink_to_an_existing_file(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)
    victim = tmp_path / "victim.db"
    victim.write_bytes(b"precious")
    target.symlink_to(victim)
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(io.BytesIO(data), target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert victim.read_bytes() == b"precious"


def test_restore_replace_keeps_a_dangling_symlink_aside(populated, tmp_path):
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)
    ghost = target.parent / "ghost-target.db"
    target.symlink_to(ghost)
    moved = dbtool.restore_database(io.BytesIO(data), target, replace=True)
    assert moved is not None and moved.is_symlink() and os.readlink(moved) == str(ghost)
    assert target.is_file() and not target.is_symlink()
    assert not ghost.exists()


def test_restore_replace_picks_an_unused_aside_name(populated, tmp_path, monkeypatch):
    """A name collision never overwrites an earlier pre-restore copy."""
    data = _backup_bytes(populated, tmp_path)
    stamp = "20260101T000000Z"

    class _FrozenDatetime:
        @staticmethod
        def now(_tz):
            return datetime(2026, 1, 1, tzinfo=UTC)

    monkeypatch.setattr(dbtool, "datetime", _FrozenDatetime)
    earlier = populated.path.parent / f"home_noc.db.pre-restore-{stamp}"
    earlier.write_bytes(b"earlier-pre-restore-copy")
    moved = dbtool.restore_database(io.BytesIO(data), populated.path, replace=True)
    assert earlier.read_bytes() == b"earlier-pre-restore-copy"
    assert moved is not None and moved != earlier and moved.exists()


def test_restore_replace_rolls_back_when_a_move_aside_fails_part_way(
    populated, tmp_path, monkeypatch
):
    data = _backup_bytes(populated, tmp_path)
    journal = populated.path.parent / "home_noc.db-journal"
    journal.write_bytes(b"old-journal")
    original = populated.path.read_bytes()
    real_link = os.link

    def flaky(src, dst, **kwargs):
        if Path(src) == populated.path:  # the journal already moved; the main file fails
            raise OSError(errno.EIO, "injected failure")
        return real_link(src, dst, **kwargs)

    monkeypatch.setattr(dbtool.os, "link", flaky)
    with pytest.raises(dbtool.DbToolError):
        dbtool.restore_database(io.BytesIO(data), populated.path, replace=True)

    assert populated.path.read_bytes() == original  # never lost, never replaced
    assert journal.read_bytes() == b"old-journal"  # the sidecar went back too
    assert _names(populated.path.parent) == {"home_noc.db", "home_noc.db-journal"}


def test_restore_replace_rolls_back_when_the_install_fails(populated, tmp_path, monkeypatch):
    data = _backup_bytes(populated, tmp_path)
    journal = populated.path.parent / "home_noc.db-journal"
    journal.write_bytes(b"old-journal")
    original = populated.path.read_bytes()
    real_link = os.link

    def flaky(src, dst, **kwargs):
        if Path(src).name.startswith(".restore-"):
            raise OSError(errno.EPERM, "injected failure")
        return real_link(src, dst, **kwargs)

    monkeypatch.setattr(dbtool.os, "link", flaky)
    with pytest.raises(dbtool.DbToolError):
        dbtool.restore_database(io.BytesIO(data), populated.path, replace=True)

    assert populated.path.read_bytes() == original
    assert journal.read_bytes() == b"old-journal"
    assert _names(populated.path.parent) == {"home_noc.db", "home_noc.db-journal"}


def test_restore_reports_preserved_files_when_rollback_is_impossible(
    populated, tmp_path, monkeypatch
):
    """If something else takes the database name mid-restore, nothing is deleted."""
    data = _backup_bytes(populated, tmp_path)
    original = populated.path.read_bytes()
    real_link = os.link

    def racy(src, dst, **kwargs):
        if Path(src).name.startswith(".restore-"):
            Path(dst).write_bytes(b"intruder")  # then the real link raises EEXIST
        return real_link(src, dst, **kwargs)

    monkeypatch.setattr(dbtool.os, "link", racy)
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(io.BytesIO(data), populated.path, replace=True)

    assert "preserved" in str(exc.value)
    assert populated.path.read_bytes() == b"intruder"  # never overwritten
    (aside,) = populated.path.parent.glob("home_noc.db.pre-restore-*")
    assert aside.read_bytes() == original  # the original is kept, never deleted
    assert str(aside) in str(exc.value)


def test_restore_fails_closed_when_hard_links_are_unavailable(populated, tmp_path, monkeypatch):
    """No silent fallback to an overwriting rename."""
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)

    def no_links(*_args, **_kwargs):
        raise OSError(errno.EPERM, "hard links not permitted")

    monkeypatch.setattr(dbtool.os, "link", no_links)
    with pytest.raises(dbtool.DbToolError, match="hard link"):
        dbtool.restore_database(io.BytesIO(data), target)
    assert _names(target.parent) == set()


def test_backup_refuses_a_dangling_symlink_destination(populated, tmp_path):
    destination = tmp_path / "link.sqlite3"
    ghost = tmp_path / "ghost.sqlite3"
    destination.symlink_to(ghost)
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.create_backup(populated.path, destination)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert destination.is_symlink() and not ghost.exists()


def test_backup_destination_race_never_overwrites(populated, tmp_path, monkeypatch):
    """The destination appears after the existence check: O_EXCL still refuses."""
    destination = tmp_path / "raced.sqlite3"
    destination.write_bytes(b"precious")
    monkeypatch.setattr(dbtool.os.path, "lexists", lambda _p: False)  # stale check result
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.create_backup(populated.path, destination)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert destination.read_bytes() == b"precious"


# --------------------------------------------------------------------------
# Pre-0005 backups: authenticate existing ciphertext before accepting a key
# --------------------------------------------------------------------------


def _legacy_backup(tmp_path: Path, monkeypatch, key: bytes, *, credentials: bool) -> bytes:
    """A backup taken at schema 0004 (no credential_key_verifier table)."""
    db_file = tmp_path / "legacy-src" / "home_noc.db"
    db_file.parent.mkdir()
    url = _migrate(monkeypatch, db_file, "0004_connector_credentials")
    assert "credential_key_verifier" not in sa.inspect(sa.create_engine(url)).get_table_names()
    if credentials:
        engine = sa.create_engine(url)
        with Session(engine) as db:
            now = datetime.now(UTC)
            cred_id = str(uuid.uuid4())
            aad = crypto.build_aad(
                credential_id=cred_id, scope_key="connector:unifi",
                credential_type="unifi_api_token",
            )
            db.add(
                models.ConnectorCredential(
                    id=cred_id, scope_key="connector:unifi", connector="unifi",
                    credential_type="unifi_api_token", enc_version=crypto.FORMAT_VERSION,
                    ciphertext=crypto.encrypt(PLAINTEXT_SECRET, aad=aad, key=key),
                    meta={}, created_at=now, updated_at=now,
                )
            )
            db.commit()
        engine.dispose()
    out = tmp_path / "legacy.sqlite3"
    dbtool.create_backup(db_file, out)
    return out.read_bytes()


def test_pre_0005_backup_is_accepted_when_its_ciphertext_authenticates(tmp_path, monkeypatch):
    key = crypto.load_key()
    data = _legacy_backup(tmp_path, monkeypatch, key, credentials=True)
    target = _volume(tmp_path, "restored")
    dbtool.restore_database(io.BytesIO(data), target)
    conn = sqlite3.connect(target)
    assert conn.execute("SELECT count(*) FROM connector_credentials").fetchone()[0] == 1
    conn.close()


def test_pre_0005_backup_is_refused_under_a_different_key(tmp_path, monkeypatch):
    key = crypto.load_key()
    data = _legacy_backup(tmp_path, monkeypatch, key, credentials=True)
    monkeypatch.setattr(settings, "credential_encryption_key", _other_key())
    target = _volume(tmp_path, "restored")
    with pytest.raises(dbtool.DbToolError) as exc:
        dbtool.restore_database(io.BytesIO(data), target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert "does not match" in str(exc.value)
    assert _names(target.parent) == set()  # nothing installed, key check was not deferred


def test_pre_0005_backup_without_credentials_has_nothing_to_authenticate(tmp_path, monkeypatch):
    data = _legacy_backup(tmp_path, monkeypatch, crypto.load_key(), credentials=False)
    monkeypatch.setattr(settings, "credential_encryption_key", _other_key())
    target = _volume(tmp_path, "restored")
    dbtool.restore_database(io.BytesIO(data), target)  # no ciphertext, any key is fine
    assert target.is_file()


def test_unverifiable_key_binding_is_refused_not_deferred(populated, tmp_path):
    conn = sqlite3.connect(populated.path)
    conn.execute("UPDATE credential_key_verifier SET version = 99")
    conn.commit()
    conn.close()
    data = _backup_bytes(populated, tmp_path)
    target = _volume(tmp_path)
    with pytest.raises(dbtool.DbToolError, match="could not verify") as exc:
        dbtool.restore_database(io.BytesIO(data), target)
    assert exc.value.code == dbtool.EXIT_REFUSED
    assert _names(target.parent) == set()


def test_check_key_cli_is_read_only_and_reports_mismatch(populated, tmp_path, monkeypatch):
    before = populated.path.read_bytes()
    assert dbtool.main(["check-key"]) == dbtool.EXIT_OK
    monkeypatch.setattr(settings, "credential_encryption_key", _other_key())
    assert dbtool.main(["check-key"]) == dbtool.EXIT_REFUSED
    assert populated.path.read_bytes() == before

    missing = tmp_path / "absent" / "nope.db"
    missing.parent.mkdir()
    monkeypatch.setattr(settings, "db_url", f"sqlite:///{missing}")
    assert dbtool.main(["check-key"]) == dbtool.EXIT_FAILURE
    assert not missing.exists()  # a read-only check never creates a database
