# backend/tests/test_devices.py
from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

client = TestClient(app)

API = "/api/v1/devices"
HEADERS = {"X-API-Key": settings.api_key or ""}


def sample():
    return {
        "hostname": "lab-switch-1",
        "ip": ["10.0.0.2"],
        "roles": ["switch"],
        "ports": [{"port": 22, "proto": "tcp", "service": "ssh", "state": "open"}],
    }


def test_devices_crud():
    # Create
    r = client.post(API, json=sample(), headers=HEADERS)
    assert r.status_code == 200
    dev = r.json()
    did = dev["id"]

    # Get
    r = client.get(f"{API}/{did}")
    assert r.status_code == 200

    # List
    r = client.get(API)
    assert r.status_code == 200
    arr = r.json()
    assert any(x["id"] == did for x in arr)

    # Update
    r = client.patch(f"{API}/{did}", json={"notes": "updated"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["notes"] == "updated"

    # Delete
    r = client.delete(f"{API}/{did}", headers=HEADERS)
    assert r.status_code == 204
