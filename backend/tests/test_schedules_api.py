"""M16 schedule API: auth/CSRF, validation, fail-closed scope, pause/resume."""
from __future__ import annotations

import pytest

from app.db import SessionLocal
from app.models import Device, Schedule

URL = "/api/v1/schedules"


@pytest.fixture(autouse=True)
def _clean():
    from app.db import Base, engine

    Base.metadata.create_all(bind=engine)
    yield
    with SessionLocal() as db:
        db.query(Schedule).delete()
        db.query(Device).delete()
        db.commit()


def make(client, **kw):
    body = {"name": "nightly", "kind": "scan", "targets": ["10.20.30.0/28"],
            "interval_seconds": 900, **kw}
    return client.post(URL, json=body, headers=client.csrf_headers)


def test_requires_session_and_csrf(anon_client):
    assert anon_client.get(URL).status_code in (401, 403)


def test_requires_csrf(client):
    assert client.post(URL, json={}).status_code == 403
    assert client.delete(f"{URL}/x").status_code == 403


def test_create_list_read_delete(client):
    r = make(client)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["enabled"] and body["profile"] == "discovery" and body["kind"] == "scan"
    assert body["next_run_at"] and body["consecutive_failures"] == 0
    sid = body["id"]
    assert [s["id"] for s in client.get(URL).json()["schedules"]] == [sid]
    assert client.get(f"{URL}/{sid}").json()["name"] == "nightly"
    assert client.delete(f"{URL}/{sid}", headers=client.csrf_headers).status_code == 204
    assert client.get(f"{URL}/{sid}").status_code == 404


@pytest.mark.parametrize("override", [
    {"interval_seconds": 299}, {"interval_seconds": 10**9}, {"profile": "security"},
    {"targets": []}, {"jitter_percent": 99}, {"name": ""}, {"kind": "nope"},
])
def test_invalid_scan_schedules_rejected(client, override):
    assert make(client, **override).status_code in (403, 422)
    assert client.get(URL).json()["schedules"] == []


def test_targets_outside_policy_rejected(client):
    assert make(client, targets=["8.8.8.0/28"]).status_code == 403
    assert make(client, targets=["not-a-cidr"]).status_code == 403


def test_unifi_sync_and_snmp_poll_validation(client):
    ok = client.post(URL, json={"name": "u", "kind": "unifi_sync", "interval_seconds": 120},
                     headers=client.csrf_headers)
    assert ok.status_code == 201 and ok.json()["profile"] is None
    assert client.post(URL, json={"name": "u", "kind": "unifi_sync", "interval_seconds": 30},
                       headers=client.csrf_headers).status_code == 422
    assert client.post(URL, json={"name": "u", "kind": "unifi_sync", "interval_seconds": 120,
                                  "targets": ["x"]},
                       headers=client.csrf_headers).status_code == 422
    assert client.post(URL, json={"name": "p", "kind": "snmp_poll", "interval_seconds": 120,
                                  "targets": ["no-such-device"]},
                       headers=client.csrf_headers).status_code == 422
    dev = client.post("/api/v1/devices", json={"hostname": "sw", "ip": ["10.20.30.9"]},
                      headers=client.csrf_headers).json()["id"]
    assert client.post(URL, json={"name": "p", "kind": "snmp_poll", "interval_seconds": 120,
                                  "targets": [dev]},
                       headers=client.csrf_headers).status_code == 201


def test_pause_and_resume_never_replays_missed_runs(client):
    sid = make(client).json()["id"]
    paused = client.patch(f"{URL}/{sid}", json={"enabled": False}, headers=client.csrf_headers)
    assert paused.json()["enabled"] is False
    with SessionLocal() as db:
        s = db.get(Schedule, sid)
        s.consecutive_failures = 5
        db.commit()
    resumed = client.patch(f"{URL}/{sid}", json={"enabled": True}, headers=client.csrf_headers)
    assert resumed.json()["enabled"] is True and resumed.json()["consecutive_failures"] == 0
    from datetime import UTC, datetime

    nxt = datetime.fromisoformat(resumed.json()["next_run_at"])
    assert 0 <= (nxt - datetime.now(UTC)).total_seconds() <= 61


def test_patch_validates_interval_and_targets(client):
    sid = make(client).json()["id"]
    assert client.patch(f"{URL}/{sid}", json={"interval_seconds": 100},
                        headers=client.csrf_headers).status_code == 422
    assert client.patch(f"{URL}/{sid}", json={"targets": ["8.8.8.0/28"]},
                        headers=client.csrf_headers).status_code == 403
    assert client.patch(f"{URL}/{sid}", json={"unknown": 1},
                        headers=client.csrf_headers).status_code == 422
    ok = client.patch(f"{URL}/{sid}", json={"interval_seconds": 600, "name": "renamed"},
                      headers=client.csrf_headers)
    assert ok.status_code == 200 and ok.json()["interval_seconds"] == 600
