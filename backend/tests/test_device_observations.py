# backend/tests/test_device_observations.py
from __future__ import annotations

from app import models
from app.config import settings
from app.db import SessionLocal

API = "/api/v1/devices"


def _headers():
    return {"X-API-Key": settings.api_key or ""}


def _create_device(client, hostname="obs-host"):
    payload = {"hostname": hostname, "ip": ["10.0.0.20"], "roles": [], "ports": []}
    return client.post(API, json=payload, headers=_headers())


def test_add_and_list_observation(client):
    r = _create_device(client)
    did = r.json()["id"]

    obs_payload = {
        "source": "scan",
        "source_ref": "job-42",
        "data": {"hostname": "obs-host", "ip": ["10.0.0.20"], "vendor": "Acme"},
    }
    r = client.post(f"{API}/{did}/observations", json=obs_payload, headers=_headers())
    assert r.status_code == 201
    body = r.json()
    assert body["device_id"] == did
    assert body["source"] == "scan"
    assert body["data"]["vendor"] == "Acme"

    r = client.get(f"{API}/{did}/observations")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["source_ref"] == "job-42"


def test_observation_defaults_observed_at_when_omitted(client):
    r = _create_device(client, hostname="obs-host-2")
    did = r.json()["id"]

    r = client.post(
        f"{API}/{did}/observations",
        json={"source": "manual", "data": {}},
        headers=_headers(),
    )
    assert r.status_code == 201
    assert r.json()["observed_at"] is not None


def test_observation_rejects_credential_keys(client):
    r = _create_device(client, hostname="obs-host-3")
    did = r.json()["id"]

    for bad_key in ("password", "community", "api_key", "token"):
        payload = {"source": "snmp", "data": {bad_key: "secret-value"}}
        r = client.post(f"{API}/{did}/observations", json=payload, headers=_headers())
        assert r.status_code == 422, f"expected rejection for key {bad_key!r}"


def test_observation_rejects_nested_credential_keys(client):
    r = _create_device(client, hostname="obs-host-nested")
    did = r.json()["id"]

    payload = {
        "source": "snmp",
        "data": {"interfaces": [{"snmp": {"community_or_user": "public"}}]},
    }
    r = client.post(f"{API}/{did}/observations", json=payload, headers=_headers())
    assert r.status_code == 422

    payload = {"source": "api", "data": {"connector": {"access-token": "secret"}}}
    r = client.post(f"{API}/{did}/observations", json=payload, headers=_headers())
    assert r.status_code == 422


def test_observation_curated_fields_not_mutated_by_raw_data(client):
    """Observations are history, not the curated asset; posting one must not
    silently change the canonical Device fields."""
    r = _create_device(client, hostname="obs-host-4")
    did = r.json()["id"]

    client.post(
        f"{API}/{did}/observations",
        json={"source": "scan", "data": {"hostname": "someone-elses-guess"}},
        headers=_headers(),
    )
    r = client.get(f"{API}/{did}")
    assert r.json()["hostname"] == "obs-host-4"


def test_observations_and_identities_cascade_deleted_with_device(client):
    r = _create_device(client, hostname="obs-host-5")
    did = r.json()["id"]

    client.post(
        f"{API}/{did}/observations",
        json={"source": "scan", "data": {}},
        headers=_headers(),
    )
    client.post(
        f"{API}/{did}/identities",
        json={"source": "serial", "external_id": "SN-cascade-1"},
        headers=_headers(),
    )

    r = client.delete(f"{API}/{did}", headers=_headers())
    assert r.status_code == 204

    db = SessionLocal()
    try:
        assert (
            db.query(models.DeviceObservation)
            .filter(models.DeviceObservation.device_id == did)
            .count()
            == 0
        )
        assert (
            db.query(models.DeviceIdentity)
            .filter(models.DeviceIdentity.device_id == did)
            .count()
            == 0
        )
    finally:
        db.close()
