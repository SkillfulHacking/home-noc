# backend/tests/test_device_identities.py
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app import models, schemas
from app.api.v1.routers.devices import _commit_or_409
from app.db import SessionLocal

API = "/api/v1/devices"


def _headers(client):
    """Unsafe methods must echo the session's CSRF token."""
    return client.csrf_headers


def _create(client, hostname="dup-host", mac=None):
    payload = {"hostname": hostname, "ip": ["10.0.0.10"], "roles": [], "ports": []}
    if mac:
        payload["mac"] = mac
    return client.post(API, json=payload, headers=_headers(client))


def test_duplicate_mac_rejected_on_create(client):
    r1 = _create(client, hostname="host-a", mac="00:11:22:33:44:55")
    assert r1.status_code == 200

    r2 = _create(client, hostname="host-b", mac="00:11:22:33:44:55")
    assert r2.status_code == 409


def test_duplicate_mac_rejected_on_update(client):
    r1 = _create(client, hostname="host-c", mac="00:11:22:33:44:66")
    assert r1.status_code == 200

    r2 = _create(client, hostname="host-d")
    assert r2.status_code == 200
    did = r2.json()["id"]

    r3 = client.patch(
        f"{API}/{did}", json={"mac": "00:11:22:33:44:66"}, headers=_headers(client)
    )
    assert r3.status_code == 409


def test_identity_listed_after_create(client):
    r = _create(client, hostname="host-e", mac="00:11:22:33:44:77")
    assert r.status_code == 200
    did = r.json()["id"]

    r = client.get(f"{API}/{did}/identities")
    assert r.status_code == 200
    rows = r.json()
    assert any(row["source"] == "mac" and row["external_id"] == "00:11:22:33:44:77" for row in rows)


def test_identity_source_case_insensitive_conflict(client):
    """A different-case source string (e.g. "MAC" vs "mac") must not bypass
    the (source, external_id) uniqueness constraint."""
    r1 = _create(client, hostname="host-h")
    r2 = _create(client, hostname="host-i")
    did1 = r1.json()["id"]
    did2 = r2.json()["id"]

    payload = {"source": "connector:unifi", "external_id": "unifi-device-999"}
    r = client.post(f"{API}/{did1}/identities", json=payload, headers=_headers(client))
    assert r.status_code == 201

    payload_upper = {"source": "CONNECTOR:UNIFI", "external_id": "unifi-device-999"}
    r = client.post(f"{API}/{did2}/identities", json=payload_upper, headers=_headers(client))
    assert r.status_code == 409


def test_mutable_network_values_cannot_be_registered_as_stable_identities(client):
    response = _create(client, hostname="host-unstable-id")
    device_id = response.json()["id"]
    for source in ("ip", "IPV6", "hostname"):
        response = client.post(
            f"{API}/{device_id}/identities",
            json={"source": source, "external_id": "192.0.2.10"},
            headers=_headers(client),
        )
        assert response.status_code == 422


def test_commit_or_409_translates_db_uniqueness_race(client):
    """Simulates two concurrent requests both passing the pre-insert conflict
    check (TOCTOU) and racing to commit: the loser must get a 409, not a
    raw IntegrityError bubbling up as a 500."""
    r = _create(client, hostname="race-host")
    did = r.json()["id"]

    db = SessionLocal()
    try:
        db.add(
            models.DeviceIdentity(
                id=schemas.new_id(), device_id=did, source="serial", external_id="race-1"
            )
        )
        db.commit()

        # A second, conflicting row added directly to bypass the route's
        # application-level pre-check and reach the DB constraint.
        db.add(
            models.DeviceIdentity(
                id=schemas.new_id(), device_id=did, source="serial", external_id="race-1"
            )
        )
        with pytest.raises(HTTPException) as exc_info:
            _commit_or_409(db, "conflict")
        assert exc_info.value.status_code == 409
    finally:
        db.rollback()
        db.close()


def test_add_connector_identity_conflict(client):
    r1 = _create(client, hostname="host-f")
    r2 = _create(client, hostname="host-g")
    did1 = r1.json()["id"]
    did2 = r2.json()["id"]

    payload = {"source": "connector:unifi", "external_id": "unifi-device-123"}
    r = client.post(f"{API}/{did1}/identities", json=payload, headers=_headers(client))
    assert r.status_code == 201

    r = client.post(f"{API}/{did2}/identities", json=payload, headers=_headers(client))
    assert r.status_code == 409
