"""M08: authorized scan scope, profiles and preflight validation."""
import logging

import pytest

from app.config import settings


@pytest.fixture(autouse=True)
def scope(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "192.168.50.0/24, 10.20.0.0/22")
    monkeypatch.setattr(settings, "scan_allow_public", False)
    monkeypatch.setattr(settings, "scan_security_profile_enabled", False)


def pre(client, targets, profile=None):
    body = {"targets": targets}
    if profile:
        body["profile"] = profile
    return client.post("/api/v1/scans/preflight", json=body, headers=client.csrf_headers)


def test_in_scope_dry_run_reports_count_and_mode(client):
    r = pre(client, ["192.168.50.0/24"])
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["mode"] == "dry-run"
    assert d["profile"] == "discovery"
    assert d["resolved_target_count"] == 254
    assert d["resolved_targets"] == ["192.168.50.0/24"]


def test_overlapping_targets_not_double_counted(client):
    r = pre(client, ["192.168.50.0/28", "192.168.50.4", "192.168.50.0/28"])
    assert r.json()["resolved_target_count"] == 14


@pytest.mark.parametrize(
    "target",
    ["192.168.51.5", "10.20.4.1", "192.168.0.0/16", "8.8.8.8", "127.0.0.1",
     "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255"],  # noqa: S104
)
def test_disallowed_targets_rejected(client, target):
    r = pre(client, [target])
    assert r.status_code in (403, 422)
    assert r.json()["detail"]["code"] in {
        "out_of_scope", "target_forbidden", "public_address", "invalid_target"
    }


@pytest.mark.parametrize(
    "target", ["example.com", "localhost", "evil.test/24", "-iL /etc/passwd",
               "192.168.50.1 --script vuln", "::1", "192.168.50.1;id", "192.168.50.5/24", ""],
)
def test_hostnames_flags_and_malformed_rejected(client, target):
    r = pre(client, [target])
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "invalid_target"


def test_public_blocked_even_if_allowlisted(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "8.8.8.0/24")
    r = pre(client, ["8.8.8.8"])
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "public_address"


def test_public_requires_both_allowlist_and_optin(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "8.8.8.0/24")
    monkeypatch.setattr(settings, "scan_allow_public", True)
    assert pre(client, ["8.8.8.8"]).status_code == 200


def test_no_scope_configured_fails_closed(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", None)
    r = pre(client, ["192.168.50.1"])
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "no_scope_configured"


def test_invalid_allowlist_entries_never_widen_scope(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "garbage, ::/0")
    assert pre(client, ["192.168.50.1"]).status_code == 403


def test_range_limit_per_profile(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "10.0.0.0/16")
    r = pre(client, ["10.0.0.0/20"])  # 4094 > discovery limit
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "range_too_large"
    r = pre(client, ["10.0.0.0/23"], "ports")  # 510 > ports limit
    assert r.json()["detail"]["code"] == "range_too_large"


def test_security_profile_is_opt_in(client, monkeypatch):
    r = pre(client, ["192.168.50.8"], "security")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "profile_disabled"
    monkeypatch.setattr(settings, "scan_security_profile_enabled", True)
    r = pre(client, ["192.168.50.8"], "security")
    assert r.status_code == 200
    assert r.json()["intrusive"] is True


def test_free_form_flags_and_unknown_profile_rejected(client):
    body = {"targets": ["192.168.50.1"], "flags": ["--script", "vuln"]}
    r = client.post("/api/v1/scans/preflight", json=body, headers=client.csrf_headers)
    assert r.status_code == 422
    assert pre(client, ["192.168.50.1"], "aggressive").status_code == 422


def test_preflight_requires_csrf(client):
    body = {"targets": ["192.168.50.1"]}
    assert client.post("/api/v1/scans/preflight", json=body).status_code == 403


def test_unauthenticated_rejected(anon_client):
    r = anon_client.post("/api/v1/scans/preflight", json={"targets": ["192.168.50.1"]})
    assert r.status_code == 401
    assert anon_client.get("/api/v1/scans/scope").status_code == 401


def test_ping_sweep_enforces_scope_in_every_mode(client):
    for dry in ("true", "false"):
        r = client.post(
            f"/api/v1/scans/ping-sweep?targets=8.8.8.8&dry_run={dry}",
            headers=client.csrf_headers,
        )
        assert r.status_code == 403
    r = client.post(
        "/api/v1/scans/ping-sweep?targets=192.168.50.1&dry_run=false",
        headers=client.csrf_headers,
    )
    assert r.status_code == 200
    assert r.json()["executed"] is False


def test_scope_endpoint_lists_profiles(client):
    d = client.get("/api/v1/scans/scope").json()
    assert d["allowed_cidrs"] == ["192.168.50.0/24", "10.20.0.0/22"]
    sec = next(p for p in d["profiles"] if p["name"] == "security")
    assert sec["enabled"] is False


def test_authorization_is_logged(client, caplog):
    with caplog.at_level(logging.INFO, logger="home_noc.scan_authorization"):
        pre(client, ["192.168.50.1"])
        pre(client, ["8.8.8.8"])
    text = caplog.text
    assert "operator=test-admin" in text
    assert "outcome=approved" in text
    assert "outcome=rejected:out_of_scope" in text
    assert "8.8.8.8" not in text


def test_too_many_entries_rejected(client):
    q = "&".join(f"targets=192.168.50.{i}" for i in range(1, 66))
    r = client.post(f"/api/v1/scans/ping-sweep?{q}", headers=client.csrf_headers)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "too_many_entries"


def test_empty_target_list_rejected(client):
    r = client.post("/api/v1/scans/preflight", json={"targets": []}, headers=client.csrf_headers)
    assert r.status_code == 422


def test_overbroad_allowlist_still_blocks_special_ranges(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "0.0.0.0/0")
    for target, code in [
        ("0.0.0.0/0", "target_forbidden"),
        ("127.0.0.0/24", "target_forbidden"),
        ("169.254.0.0/24", "target_forbidden"),
        ("0.0.0.1", "target_forbidden"),
        ("0.0.0.4/30", "target_forbidden"),
        ("0.255.255.255", "target_forbidden"),
        ("169.0.0.0/8", "target_forbidden"),  # contains link-local, endpoints outside
        ("10.0.0.0/8", "range_too_large"),
        ("1.1.1.1", "public_address"),
    ]:
        r = pre(client, [target])
        assert r.status_code in (403, 422), target
        assert r.json()["detail"]["code"] == code, target


def test_allowlist_accepts_json_list(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", '["192.168.50.0/24"]')
    assert pre(client, ["192.168.50.9"]).status_code == 200
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "[not json")
    assert pre(client, ["192.168.50.9"]).status_code == 403


def test_defaults_are_safe():
    from app.config import Settings

    s = Settings(_env_file=None)
    assert s.scan_allow_public is False
    assert s.scan_security_profile_enabled is False


def test_profile_argv_is_fixed_and_non_intrusive_by_default():
    from app.scan_scope import PROFILES, ScanProfile

    assert "-sV" not in PROFILES[ScanProfile.DISCOVERY].argv
    assert "-sV" not in PROFILES[ScanProfile.PORTS].argv
    assert not PROFILES[ScanProfile.DISCOVERY].intrusive
    assert not PROFILES[ScanProfile.PORTS].intrusive
    assert PROFILES[ScanProfile.SECURITY].intrusive
    for spec in PROFILES.values():
        assert not any("script" in a or a == "-A" for a in spec.argv)
