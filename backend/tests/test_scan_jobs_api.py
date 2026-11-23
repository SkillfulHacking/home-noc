"""Start/status/events/cancel endpoints for scan jobs (M09)."""
from __future__ import annotations

import pytest

from app import jobs
from app.db import SessionLocal
from app.models import JobEvent, ScanJob

URL = "/api/v1/scans/jobs"
BODY = {"targets": ["10.77.0.0/28"], "profile": "discovery"}


@pytest.fixture(autouse=True)
def _clean_jobs(job_env):
    yield
    with SessionLocal() as db:
        db.query(JobEvent).delete()
        db.query(ScanJob).delete()
        db.commit()


def start(client, body=BODY):
    return client.post(URL, json=body, headers=client.csrf_headers)


def test_every_job_route_requires_a_session(anon_client):
    assert anon_client.post(URL, json=BODY).status_code == 401
    assert anon_client.get(URL).status_code == 401
    assert anon_client.get(f"{URL}/abc").status_code == 401
    assert anon_client.get(f"{URL}/abc/events").status_code == 401
    assert anon_client.post(f"{URL}/abc/cancel").status_code == 401


def test_unsafe_job_routes_require_csrf(client):
    assert client.post(URL, json=BODY).status_code == 403
    job_id = start(client).json()["id"]
    assert client.post(f"{URL}/{job_id}/cancel").status_code == 403


def test_start_returns_queued_job_without_internal_fields(client):
    resp = start(client)
    assert resp.status_code == 202, resp.text
    job = resp.json()
    assert job["status"] == "queued" and job["targets"] == ["10.77.0.0/28"]
    assert job["progress"] == {"done": 0, "total": 16, "percent": 0}
    assert job["created_by"] == "test-admin" and job["max_attempts"] == 3
    assert not {"lease_owner", "lease_expires_at", "runner_pid"} & set(job)
    assert client.get(f"{URL}/{job['id']}").json()["id"] == job["id"]


def test_out_of_scope_and_unconfigured_scope_are_rejected_and_not_queued(client, job_env):
    resp = start(client, {"targets": ["10.78.0.0/28"], "profile": "discovery"})
    assert resp.status_code == 403 and resp.json()["detail"]["code"] == "out_of_scope"
    job_env.scan_allowed_cidrs_raw = None
    resp = start(client)
    assert resp.status_code == 403 and resp.json()["detail"]["code"] == "no_scope_configured"
    assert client.get(URL).json()["items"] == []


def test_intrusive_profile_stays_disabled_and_flags_are_rejected(client):
    resp = start(client, {"targets": ["10.77.0.0/28"], "profile": "security"})
    assert resp.status_code == 403 and resp.json()["detail"]["code"] == "profile_disabled"
    resp = start(client, {**BODY, "args": ["--script", "vuln"]})
    assert resp.status_code == 422


def test_active_job_limit_returns_429(client, job_env):
    job_env.scan_max_active_jobs = 2
    assert start(client).status_code == 202
    assert start(client).status_code == 202
    resp = start(client)
    assert resp.status_code == 429
    assert resp.json()["detail"]["code"] == "too_many_active_jobs"
    assert len(client.get(URL).json()["items"]) == 2


def test_list_filters_by_status_and_validates_input(client):
    a = start(client).json()["id"]
    start(client)
    client.post(f"{URL}/{a}/cancel", headers=client.csrf_headers)
    items = client.get(URL, params={"status": "cancelled"}).json()["items"]
    assert [j["id"] for j in items] == [a]
    assert client.get(URL, params={"status": "bogus"}).status_code == 422
    assert client.get(URL, params={"limit": 0}).status_code == 422


def test_unknown_job_is_404(client):
    assert client.get(f"{URL}/{'0' * 36}").status_code == 404
    assert client.get(f"{URL}/{'0' * 36}/events").status_code == 404
    assert client.post(f"{URL}/{'0' * 36}/cancel", headers=client.csrf_headers).status_code == 404
    assert client.get(f"{URL}/{'0' * 40}").status_code == 422


def test_cancel_queued_job_is_idempotent(client):
    job_id = start(client).json()["id"]
    first = client.post(f"{URL}/{job_id}/cancel", headers=client.csrf_headers)
    assert first.status_code == 200 and first.json()["status"] == "cancelled"
    again = client.post(f"{URL}/{job_id}/cancel", headers=client.csrf_headers)
    assert again.status_code == 200 and again.json()["status"] == "cancelled"


def test_cancel_running_job_reports_cancelling_until_worker_stops_it(client):
    job_id = start(client).json()["id"]
    with SessionLocal() as db:
        assert jobs.claim_next(db, "w1").id == job_id
    resp = client.post(f"{URL}/{job_id}/cancel", headers=client.csrf_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelling" and resp.json()["cancel_requested"] is True
    with SessionLocal() as db:
        assert jobs.heartbeat(db, job_id, "w1") == "cancel"


def test_cancel_after_completion_is_409(client):
    job_id = start(client).json()["id"]
    with SessionLocal() as db:
        jobs.claim_next(db, "w1")
        jobs.finish(db, job_id, "w1", jobs.JobStatus.SUCCEEDED, result={"hosts_up": 0})
    resp = client.post(f"{URL}/{job_id}/cancel", headers=client.csrf_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["code"] == "job_finished"


def test_events_are_pollable_with_a_cursor(client):
    job_id = start(client).json()["id"]
    first = client.get(f"{URL}/{job_id}/events").json()
    assert [e["type"] for e in first["events"]] == ["queued"]
    assert first["terminal"] is False and first["status"] == "queued"
    cursor = first["next_after"]

    with SessionLocal() as db:
        jobs.claim_next(db, "w1")
        jobs.update_progress(db, job_id, "w1", 8, 16)
        jobs.finish(db, job_id, "w1", jobs.JobStatus.SUCCEEDED)

    page = client.get(f"{URL}/{job_id}/events", params={"after": cursor}).json()
    assert [e["type"] for e in page["events"]] == ["started", "succeeded"]
    assert page["terminal"] is True and page["next_after"] > cursor
    empty = client.get(f"{URL}/{job_id}/events", params={"after": page["next_after"]}).json()
    assert empty["events"] == [] and empty["next_after"] == page["next_after"]

    status = client.get(f"{URL}/{job_id}").json()
    assert status["status"] == "succeeded" and status["progress"]["percent"] == 100
    assert client.get(f"{URL}/{job_id}/events", params={"limit": 0}).status_code == 422
