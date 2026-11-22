# backend/tests/test_device_read_hardening.py
from __future__ import annotations

from uuid import uuid4

from app import models
from app.config import settings
from app.db import SessionLocal

API = "/api/v1/devices"


def _headers():
    return {"X-API-Key": settings.api_key or ""}


def _create(client, hostname, mac=None):
    payload = {"hostname": hostname, "ip": ["10.0.0.10"], "roles": [], "ports": []}
    if mac:
        payload["mac"] = mac
    return client.post(API, json=payload, headers=_headers())


def _insert_raw_device(**overrides) -> str:
    """Write a Device row directly, bypassing schema validation, to simulate
    data stored before migration 0002's stricter normalization landed."""
    device_id = str(uuid4())
    db = SessionLocal()
    try:
        db.add(models.Device(id=device_id, **overrides))
        db.commit()
    finally:
        db.close()
    return device_id


def test_patch_normalizes_stale_legacy_mac_before_identity_sync(client):
    """A PATCH that doesn't touch `mac` must not let a device with an
    unnormalized legacy mac bypass the (source="mac", external_id)
    uniqueness check against an already-normalized identity."""
    r = _create(client, hostname="normalized-owner", mac="02:00:00:00:99:01")
    assert r.status_code == 200

    legacy_id = _insert_raw_device(
        hostname="legacy-mac-host",
        mac="02-00-00-00-99-01",
        ip={"v": []},
        roles={"v": []},
        ports={"v": []},
    )

    r = client.patch(
        f"{API}/{legacy_id}", json={"hostname": "legacy-mac-host-renamed"}, headers=_headers()
    )
    assert r.status_code == 409


def test_legacy_non_conforming_row_does_not_500_list_or_get(client):
    legacy_id = _insert_raw_device(
        hostname="legacy-bad-data",
        ip={"v": ["10.0.0.5", "not-an-ip"]},
        mac="not-a-mac",
        discovery_method="telnet-scan",
        roles={"v": ["switch", "toaster"]},
        ports={"v": [
            {"port": 22, "proto": "tcp", "state": "open"},
            {"port": 23, "proto": "sctp"},
        ]},
        api={"type": "rest", "url": "https://admin:hunter2@10.0.0.5/api"},
        snmp={"enabled": True, "version": "v2c", "community_or_user": "public"},
    )

    r = client.get(API)
    assert r.status_code == 200
    rows = {row["id"]: row for row in r.json()}
    assert legacy_id in rows

    r = client.get(f"{API}/{legacy_id}")
    assert r.status_code == 200
    body = r.json()

    assert body["mac"] is None
    assert body["ip"] == ["10.0.0.5"]
    assert body["discovery_method"] is None
    assert body["roles"] == ["switch"]
    assert body["ports"] == [{"port": 22, "proto": "tcp", "service": None, "state": "open"}]
    assert body["snmp"] is None
    assert body["api"] is not None
    assert "hunter2" not in str(body["api"])
    assert body["api"]["url"] is None


def test_identity_and_observation_reads_require_api_key_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "test-secret-key")
    headers = {"X-API-Key": "test-secret-key"}

    response = client.post(
        API,
        json={"hostname": "auth-read-host", "ip": [], "roles": [], "ports": []},
        headers=headers,
    )
    assert response.status_code == 200
    device_id = response.json()["id"]

    assert client.get(f"{API}/{device_id}/identities").status_code == 401
    assert client.get(f"{API}/{device_id}/observations").status_code == 401
    assert client.get(f"{API}/{device_id}/identities", headers=headers).status_code == 200
    assert client.get(f"{API}/{device_id}/observations", headers=headers).status_code == 200


