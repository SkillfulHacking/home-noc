"""M27 security regression tests: scan-scope bypass, API docs exposure, log redaction."""
from __future__ import annotations

import base64
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from app import auth
from app.scan_scope import ScanProfile, ScopeError, resolve_targets

pytestmark = pytest.mark.usefixtures("job_env")  # authorizes 10.77.0.0/24 only

BYPASS_ATTEMPTS = [
    # outside the deployment ceiling, including just-outside and widening
    "10.77.1.1", "10.77.0.0/16", "10.0.0.0/8", "192.168.1.1", "8.8.8.8", "0.0.0.0/0", "0.0.0.0",  # noqa: S104 - a rejected target, not a bind
    # special ranges that must never be scan targets
    "127.0.0.1", "127.0.0.0/8", "169.254.169.254", "224.0.0.1", "255.255.255.255", "100.64.0.1",
    # alternative spellings / encodings of addresses
    "0x0a4d0001", "167903233", "010.077.000.001", "10.77.0.1.", "10.77.1", "10.77.0.256",
    "１０.７７.０.１", "10.77.0.1%00", "::1", "::ffff:10.77.0.1", "fe80::1",
    # injection / flag-shaped / multi-value strings
    "-oN /tmp/x", "--script=vuln", "10.77.0.1 8.8.8.8", "10.77.0.1,8.8.8.8", "10.77.0.1;8.8.8.8",
    "10.77.0.1\n8.8.8.8", "10.77.0.1|id", "$(id)", "`id`", "10.77.0.1 -p-", "10.77.0.1:80",
    "http://10.77.0.1", "10.77.0.1/24 ", " ", "", "x" * 100,
    # hostnames are never resolved
    "localhost", "example.com", "router.local", "metadata.google.internal",
    # malformed CIDRs (strict parsing: host bits set, bad prefixes)
    "10.77.0.1/24", "10.77.0.0/33", "10.77.0.0/-1", "10.77.0.0/",
]


@pytest.mark.parametrize("target", BYPASS_ATTEMPTS)
@pytest.mark.parametrize("profile", [ScanProfile.DISCOVERY, ScanProfile.PORTS])
def test_target_bypass_attempts_are_rejected(target, profile):
    with pytest.raises(ScopeError):
        resolve_targets([target], profile)


def test_one_bad_entry_poisons_the_whole_request():
    with pytest.raises(ScopeError):
        resolve_targets(["10.77.0.5", "8.8.8.8"], ScanProfile.DISCOVERY)


def test_entry_count_is_bounded():
    with pytest.raises(ScopeError):
        resolve_targets([f"10.77.0.{i % 200}" for i in range(65)], ScanProfile.DISCOVERY)


def test_inside_the_ceiling_still_works():
    nets, count = resolve_targets(["10.77.0.5", "10.77.0.8/30"], ScanProfile.DISCOVERY)
    assert count >= 3 and all(str(n).startswith("10.77.0.") for n in nets)


def test_public_targets_never_reach_intrusive_profiles(monkeypatch):
    from app import scan_scope

    monkeypatch.setattr(scan_scope.settings, "scan_vuln_profile_enabled", True)
    with pytest.raises(ScopeError):
        resolve_targets(["8.8.8.8"], ScanProfile.VULN)


# -------------------------------------------------------------- API docs ---

def _run_prod(code: str) -> str:
    """Import the app in a fresh interpreter configured like production."""
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    env = {
        "PATH": os.environ["PATH"], "HOME": str(Path.cwd()), "APP_ENV": "prod", "DB_URL": "sqlite://",
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD_HASH": auth.hash_password("correct horse battery", iterations=100_000),
        "CREDENTIAL_ENCRYPTION_KEY": key,
    }
    root = str(Path(__file__).resolve().parents[1])
    script = f"import sys; sys.path.insert(0, {root!r})\n{code}"
    done = subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-c", script], capture_output=True, text=True, env=env, timeout=60,
        check=False)
    assert done.returncode == 0, done.stderr[-800:]
    return done.stdout.strip()


def test_production_exposes_no_interactive_docs_or_schema_endpoint():
    out = _run_prod(
        "from fastapi.testclient import TestClient\n"
        "from app.main import app\n"
        "c = TestClient(app)\n"
        "print([c.get(p).status_code for p in ('/docs', '/redoc', '/openapi.json')])\n")
    assert out == "[404, 404, 404]"


def test_development_keeps_the_docs_for_developers():
    from fastapi.testclient import TestClient

    from app.main import app

    assert TestClient(app).get("/openapi.json").status_code == 200


# --------------------------------------------------------- log redaction ---

def test_secrets_never_reach_logs_during_credential_and_connector_flows(client, caplog):
    secrets = ["LOG-CANARY-TOKEN-0123456789", "LOG-CANARY-AUTH-pass1234",
               "LOG-CANARY-PRIV-pass1234"]
    caplog.set_level(logging.DEBUG)
    dev = client.post("/api/v1/devices", json={"hostname": "logcheck", "ip": ["10.77.0.50"]},
                      headers=client.csrf_headers).json()["id"]
    client.put("/api/v1/credentials/connectors/unifi/unifi_api_token",
               json={"secret": {"token": secrets[0]}}, headers=client.csrf_headers)
    client.put(f"/api/v1/credentials/devices/{dev}/snmpv3_auth", headers=client.csrf_headers,
               json={"secret": {"password": secrets[1]},
                     "metadata": {"username": "monitor", "protocol": "SHA256"}})
    client.put(f"/api/v1/credentials/devices/{dev}/snmpv3_priv", headers=client.csrf_headers,
               json={"secret": {"password": secrets[2]}, "metadata": {"protocol": "AES128"}})
    # Rejected requests echo nothing either (validation errors are scrubbed).
    bad = client.put(f"/api/v1/credentials/devices/{dev}/snmpv3_auth", headers=client.csrf_headers,
                     json={"secret": {"password": "Cn-1234"}, "metadata": {"username": "m"}})
    assert bad.status_code == 422 and "Cn-1234" not in bad.text
    client.get(f"/api/v1/credentials/devices/{dev}")
    client.post(f"/api/v1/devices/{dev}/snmp/test", json={}, headers=client.csrf_headers)
    client.put("/api/v1/connectors/unifi", headers=client.csrf_headers,
               json={"enabled": False, "base_url": "https://10.77.0.1", "verify_tls": True})
    logged = "\n".join(r.getMessage() + str(r.args) for r in caplog.records)
    for secret in secrets:
        assert secret not in logged
