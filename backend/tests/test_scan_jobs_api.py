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


# ------------------------------------------------ M08A scan policy API
POLICY = "/api/v1/scan-policy"


def put_policy(client, revision=1, **over):
    body = {
        "expected_revision": revision, "private_enabled": True, "private_allowlist": [],
        "public_enabled": False, "public_allowlist": [], "exclusions": [],
    }
    body.update(over)
    return client.put(POLICY, json=body, headers=client.csrf_headers)


def test_policy_routes_deny_anonymous(anon_client):
    assert anon_client.get(POLICY).status_code == 401
    assert anon_client.get(f"{POLICY}/audit").status_code == 401
    assert anon_client.put(POLICY, json={}).status_code == 401


def test_policy_write_requires_csrf_header(client):
    r = client.put(POLICY, json={"expected_revision": 1, "private_enabled": True})
    assert r.status_code == 403
    assert client.get(POLICY).json()["revision"] == 1


def test_policy_routes_are_admin_only(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "admin_username", "someone-else")
    assert client.get(POLICY).status_code == 403
    assert client.get(POLICY).json()["detail"]["code"] == "admin_required"
    assert put_policy(client).status_code == 403
    assert client.get(f"{POLICY}/audit").status_code == 403


def test_fresh_install_reads_default_policy_without_secrets(client, job_env):
    r = client.get(POLICY)
    assert r.status_code == 200
    d = r.json()
    assert d["revision"] == 1 and d["private"]["enabled"] is True
    assert d["public"]["enabled"] is False and d["effective"]["public_scanning"] is False
    assert d["private"]["rfc1918"] == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert d["deployment"]["allowed_cidrs"] == ["10.77.0.0/24"]
    text = r.text.lower()
    assert "password" not in text and "pbkdf2" not in text and "secret" not in text


def test_openapi_documents_policy_routes_and_errors():
    from app.main import app

    spec = app.openapi()
    assert {"get", "put"} <= set(spec["paths"][POLICY])
    assert "get" in spec["paths"][f"{POLICY}/audit"]
    put = spec["paths"][POLICY]["put"]
    assert {"401", "403", "409", "422", "503"} <= set(put["responses"])
    schema = spec["components"]["schemas"]["PolicyUpdate"]
    assert {"expected_revision", "confirm_broadening", "confirm_public"} <= set(
        schema["properties"]
    )


def test_fresh_private_scan_needs_no_environment_scope(client, job_env):
    job_env.scan_allowed_cidrs_raw = None
    assert start(client).status_code == 202


def test_put_applies_bumps_revision_and_is_audited(client):
    r = put_policy(client, exclusions=["10.77.0.200/32"])
    assert r.status_code == 200 and r.json()["revision"] == 2
    audit = client.get(f"{POLICY}/audit").json()["items"]
    assert audit[0]["outcome"] == "applied" and audit[0]["actor"] == "test-admin"
    assert audit[0]["prior_revision"] == 1 and audit[0]["new_revision"] == 2
    assert audit[0]["prior"]["exclusions"] == [] and audit[0]["new"]["exclusions"] == [
        "10.77.0.200/32"
    ]


def test_stale_revision_conflicts_and_returns_current_policy(client):
    assert put_policy(client, exclusions=["10.77.0.200/32"]).status_code == 200
    r = put_policy(client, revision=1, private_enabled=False)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["code"] == "revision_conflict" and detail["current"]["revision"] == 2
    assert client.get(POLICY).json()["private"]["enabled"] is True  # nothing applied


def test_invalid_policy_is_rejected_atomically_and_audited(client):
    r = put_policy(client, private_allowlist=["8.8.8.0/24"])
    assert r.status_code == 422
    assert r.json()["detail"] == {
        "code": "not_rfc1918", "message": r.json()["detail"]["message"],
        "field": "private_allowlist",
    }
    assert client.get(POLICY).json()["revision"] == 1
    outcomes = [a["outcome"] for a in client.get(f"{POLICY}/audit").json()["items"]]
    assert outcomes == ["rejected:not_rfc1918"]
    # outside the immutable environment ceiling (10.77.0.0/24)
    r = put_policy(client, private_allowlist=["192.168.1.0/24"])
    assert r.json()["detail"]["code"] == "outside_deployment_ceiling"
    assert put_policy(client, extra_field=1).status_code == 422


def test_broadening_requires_explicit_confirmation(client):
    r = put_policy(client, private_enabled=False)
    assert r.status_code == 200  # narrowing needs no confirmation
    r = put_policy(client, revision=2, private_enabled=True)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "confirmation_required"
    r = put_policy(client, revision=2, private_enabled=True, confirm_broadening=True)
    assert r.status_code == 200 and r.json()["private"]["enabled"] is True


def test_public_enablement_needs_public_confirmation(client, job_env):
    job_env.scan_allowed_cidrs_raw = None
    body = dict(public_enabled=True, public_allowlist=["8.8.8.0/24"], confirm_broadening=True)
    r = put_policy(client, **body)
    assert r.status_code == 409 and r.json()["detail"]["public_confirmation_required"] is True
    assert put_policy(client, confirm_public=True, **body).status_code == 200
    ok = client.post("/api/v1/scans/preflight", json={"targets": ["8.8.8.8"]},
                     headers=client.csrf_headers)
    assert ok.status_code == 200
    assert put_policy(client, revision=2, public_enabled=False,
                      public_allowlist=["8.8.8.0/24"]).status_code == 200
    denied = client.post("/api/v1/scans/preflight", json={"targets": ["8.8.8.8"]},
                         headers=client.csrf_headers)
    assert denied.status_code == 403 and denied.json()["detail"]["code"] == "public_address"


def test_saving_policy_fails_queued_jobs_it_no_longer_authorizes(client):
    keep = start(client, {"targets": ["10.77.0.64/28"], "profile": "discovery"}).json()["id"]
    revoked = start(client).json()["id"]  # 10.77.0.0/28
    assert put_policy(client, exclusions=["10.77.0.0/30"]).status_code == 200
    gone = client.get(f"{URL}/{revoked}").json()
    assert gone["status"] == "failed" and gone["error_code"] == "authorization_revoked"
    assert client.get(f"{URL}/{keep}").json()["status"] == "queued"
    with SessionLocal() as db:
        assert "failed" in [e.type for e in jobs.list_events(db, revoked)]


def test_unreadable_policy_store_denies_scans_and_settings(client, monkeypatch):
    from app import scan_policy

    def down(*_a, **_k):
        raise scan_policy.PolicyUnavailable(
            "policy_unavailable", "store down", transient=True
        )

    monkeypatch.setattr(scan_policy, "load_policy", down)
    r = start(client)
    assert r.status_code == 503 and r.json()["detail"]["code"] == "policy_unavailable"
    assert client.get(POLICY).status_code == 503
    assert put_policy(client).status_code == 503
    scope = client.get("/api/v1/scans/scope").json()
    assert scope["policy"] is None and scope["policy_error"]["code"] == "policy_unavailable"


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
    # A legacy/upgraded install (private scanning seeded off) stays denied.
    from conftest import set_policy

    with SessionLocal() as db:
        set_policy(db, private_enabled=False)
    resp = start(client)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "private_scanning_disabled"
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
