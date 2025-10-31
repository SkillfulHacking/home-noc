# backend/tests/test_devices.py
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)
API = "/api/v1/devices"
HEADERS = {"X-API-Key": settings.api_key or "changeme-please-32bytes-min"}

def sample():
    return {
        "hostname": "lab-switch-1",
        "ip": ["10.0.0.2"],
        "mac": "00:11:22:33:44:55",
        "first_seen": "2025-10-30T00:00:00Z",
        "last_seen": "2025-10-30T01:00:00Z",
        "discovery_method": "scan",
        "vendor": "Zyxel",
        "model": "GS1900",
        "os": "switch-os",
        "serial": "XYZ",
        "location": "Basement rack",
        "roles": ["switch"],
        "ports": [{"port": 22, "proto": "tcp", "service": "ssh", "state": "open"}],
        "snmp": {"enabled": True, "version": "v2c", "community_or_user": "****"},
        "api": {"type": "rest", "url": "****"},
        "notes": "seed device"
    }

def test_crud_device():
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
