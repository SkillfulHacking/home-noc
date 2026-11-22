# backend/tests/test_devices.py
from __future__ import annotations

API = "/api/v1/devices"


def sample():
    return {
        "hostname": "lab-switch-1",
        "ip": ["10.0.0.2"],
        "roles": ["switch"],
        "ports": [{"port": 22, "proto": "tcp", "service": "ssh", "state": "open"}],
    }


def test_devices_crud(client):
    headers = client.csrf_headers
    # Create
    r = client.post(API, json=sample(), headers=headers)
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
    r = client.patch(f"{API}/{did}", json={"notes": "updated"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["notes"] == "updated"

    # Delete
    r = client.delete(f"{API}/{did}", headers=headers)
    assert r.status_code == 204


def test_put_round_trip_with_populated_ports(client):
    """Regression test: PUT previously raised because the handler called
    .model_dump() a second time on already-dumped port dicts."""
    headers = client.csrf_headers
    r = client.post(API, json=sample(), headers=headers)
    assert r.status_code == 200
    did = r.json()["id"]

    replacement = sample()
    replacement["hostname"] = "lab-switch-1-renamed"
    replacement["ports"] = [
        {"port": 22, "proto": "tcp", "service": "ssh", "state": "open"},
        {"port": 443, "proto": "tcp", "service": "https", "state": "open"},
    ]
    r = client.put(f"{API}/{did}", json=replacement, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["hostname"] == "lab-switch-1-renamed"
    assert len(body["ports"]) == 2
    assert {p["port"] for p in body["ports"]} == {22, 443}


def test_patch_round_trip_with_populated_ports(client):
    """Regression test: PATCH previously raised on the same double-dump bug."""
    headers = client.csrf_headers
    r = client.post(API, json=sample(), headers=headers)
    assert r.status_code == 200
    did = r.json()["id"]

    r = client.patch(
        f"{API}/{did}",
        json={"ports": [{"port": 8080, "proto": "tcp", "service": "http-alt"}]},
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["ports"]) == 1
    assert body["ports"][0]["port"] == 8080
