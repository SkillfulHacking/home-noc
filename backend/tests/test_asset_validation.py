# backend/tests/test_asset_validation.py
from __future__ import annotations

from app.config import settings

API = "/api/v1/devices"


def sample(**overrides):
    base = {
        "hostname": "lab-switch-2",
        "ip": ["10.0.0.3"],
        "roles": ["switch"],
        "ports": [{"port": 22, "proto": "tcp", "service": "ssh", "state": "open"}],
    }
    base.update(overrides)
    return base


def _headers():
    return {"X-API-Key": settings.api_key or ""}


def test_invalid_ip_rejected(client):
    r = client.post(API, json=sample(ip=["not-an-ip"]), headers=_headers())
    assert r.status_code == 422


def test_mac_normalized_to_lowercase_colon_form(client):
    r = client.post(API, json=sample(mac="AA-BB-CC-DD-EE-FF"), headers=_headers())
    assert r.status_code == 200
    assert r.json()["mac"] == "aa:bb:cc:dd:ee:ff"


def test_invalid_mac_rejected(client):
    r = client.post(API, json=sample(mac="not-a-mac"), headers=_headers())
    assert r.status_code == 422


def test_invalid_port_number_rejected(client):
    payload = sample(ports=[{"port": 70000, "proto": "tcp"}])
    r = client.post(API, json=payload, headers=_headers())
    assert r.status_code == 422


def test_invalid_port_proto_rejected(client):
    payload = sample(ports=[{"port": 22, "proto": "icmp"}])
    r = client.post(API, json=payload, headers=_headers())
    assert r.status_code == 422


def test_naive_timestamp_normalized_to_utc(client):
    r = client.post(
        API,
        json=sample(first_seen="2025-01-01T00:00:00"),
        headers=_headers(),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["first_seen"].endswith("+00:00") or body["first_seen"].endswith("Z")


def test_timezone_round_trips_through_get(client):
    r = client.post(
        API,
        json=sample(first_seen="2025-01-01T12:00:00+05:00"),
        headers=_headers(),
    )
    assert r.status_code == 200
    did = r.json()["id"]

    r = client.get(f"{API}/{did}")
    assert r.status_code == 200
    first_seen = r.json()["first_seen"]
    # Normalized to UTC: 12:00+05:00 == 07:00Z
    assert "07:00:00" in first_seen


def test_snmp_community_secret_rejected(client):
    """Legacy/unexpected snmp fields (e.g. a credential) must be rejected
    outright, not silently dropped, so a caller can't assume it was stored."""
    payload = sample()
    payload["snmp"] = {"enabled": True, "version": "v2c", "community_or_user": "public"}
    r = client.post(API, json=payload, headers=_headers())
    assert r.status_code == 422


def test_api_url_with_embedded_credentials_rejected(client):
    payload = sample()
    payload["api"] = {"type": "rest", "url": "https://admin:hunter2@10.0.0.3/api"}
    r = client.post(API, json=payload, headers=_headers())
    assert r.status_code == 422


def test_api_secret_fields_and_credential_query_rejected(client):
    payload = sample(api={"type": "rest", "token": "secret"})
    assert client.post(API, json=payload, headers=_headers()).status_code == 422

    payload = sample(api={"type": "rest", "url": "https://controller.test/api?access_token=x"})
    assert client.post(API, json=payload, headers=_headers()).status_code == 422


def test_unknown_secret_fields_rejected_at_all_asset_levels(client):
    assert client.post(
        API, json={**sample(), "api_key": "secret"}, headers=_headers()
    ).status_code == 422
    payload = sample(ports=[{"port": 22, "proto": "tcp", "password": "secret"}])
    assert client.post(API, json=payload, headers=_headers()).status_code == 422


def test_snmp_missing_value_sentinels_are_not_stored_as_hardware(client):
    payload = sample(
        vendor="No Such Object currently exists at this OID",
        model="No Such Instance currently exists at this OID",
        serial="  serial-123  ",
    )
    response = client.post(API, json=payload, headers=_headers())
    assert response.status_code == 200
    assert response.json()["vendor"] is None
    assert response.json()["model"] is None
    assert response.json()["serial"] == "serial-123"
