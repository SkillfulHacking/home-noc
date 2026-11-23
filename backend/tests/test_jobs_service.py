"""Job queue state machine, leasing, caps, retries and recovery (M09)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from app import jobs
from app.jobs import JobStatus
from app.models import JobEvent, ScanJob

pytestmark = pytest.mark.usefixtures("job_env")


def make_job(db, targets=("10.77.0.0/28",)):
    return jobs.enqueue_scan(
        db, profile="discovery", targets=list(targets), progress_total=16, created_by="tester"
    )


def expire_lease(db, job_id):
    db.execute(
        update(ScanJob).where(ScanJob.id == job_id)
        .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=5))
    )
    db.commit()


def event_types(db, job_id):
    return [e.type for e in jobs.list_events(db, job_id)]


def test_lifecycle_persists_events(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        assert job.status == "queued" and job.attempts == 0
        claimed = jobs.claim_next(db, "w1")
        assert claimed.id == job.id and claimed.status == "running" and claimed.attempts == 1
        jobs.update_progress(db, job.id, "w1", 8, 16)
        assert jobs.finish(db, job.id, "w1", JobStatus.SUCCEEDED, result={"hosts_up": 0})
        done = db.get(ScanJob, job.id)
        db.refresh(done)
        assert done.status == "succeeded" and done.progress_done == 8
        assert done.lease_owner is None and done.finished_at is not None
        assert event_types(db, job.id) == ["queued", "started", "succeeded"]


def test_event_cursor_returns_only_newer(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        first = jobs.list_events(db, job.id)
        newer = jobs.list_events(db, job.id, after=first[0].id)
        assert [e.type for e in newer] == ["started"]
        assert jobs.list_events(db, job.id, after=first[-1].id) == []


def test_concurrent_job_cap_is_enforced_in_claim(job_session_factory):
    with job_session_factory() as db:
        a, b = make_job(db), make_job(db)
        first = jobs.claim_next(db, "w1")
        assert first.id == a.id
        # A different worker is held to the same global cap.
        assert jobs.claim_next(db, "w2") is None
        assert jobs.finish(db, a.id, "w1", JobStatus.SUCCEEDED)
        assert jobs.claim_next(db, "w2").id == b.id


def test_cap_allows_configured_parallelism(job_session_factory, job_env, monkeypatch):
    monkeypatch.setattr(job_env, "worker_max_concurrent_jobs", 2)
    with job_session_factory() as db:
        for _ in range(3):
            make_job(db)
        assert jobs.claim_next(db, "w1") and jobs.claim_next(db, "w2")
        assert jobs.claim_next(db, "w3") is None


def test_queue_limit(job_session_factory, job_env, monkeypatch):
    monkeypatch.setattr(job_env, "scan_max_active_jobs", 2)
    with job_session_factory() as db:
        make_job(db)
        make_job(db)
        with pytest.raises(jobs.QueueFull):
            make_job(db)


def test_cancel_queued_ends_immediately(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        out = jobs.request_cancel(db, job.id)
        assert out.status == "cancelled" and out.finished_at is not None
        assert jobs.claim_next(db, "w1") is None
        assert jobs.request_cancel(db, "nope") is None


def test_cancel_running_is_seen_by_heartbeat_then_finishes(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        assert jobs.heartbeat(db, job.id, "w1") == "ok"
        assert jobs.request_cancel(db, job.id).status == "cancelling"
        assert jobs.heartbeat(db, job.id, "w1") == "cancel"
        assert jobs.finish(db, job.id, "w1", JobStatus.CANCELLED)
        assert db.get(ScanJob, job.id).status == "cancelled"
        # Cancelling an already-cancelled job is a stable no-op.
        assert jobs.request_cancel(db, job.id).status == "cancelled"


def test_retry_uses_backoff_and_is_bounded(job_session_factory, job_env, monkeypatch):
    monkeypatch.setattr(job_env, "scan_job_max_attempts", 2)
    monkeypatch.setattr(job_env, "scan_job_retry_backoff_seconds", 60.0)
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        assert jobs.retry_or_fail(
            db, job.id, "w1", error_code="scanner_failed", error_message="x", retryable=True
        ) == "queued"
        assert jobs.claim_next(db, "w1") is None  # backing off

        monkeypatch.setattr(job_env, "scan_job_retry_backoff_seconds", 0.0)
        db.execute(update(ScanJob).where(ScanJob.id == job.id)
                   .values(available_at=datetime.now(UTC)))
        db.commit()
        assert jobs.claim_next(db, "w1").attempts == 2
        assert jobs.retry_or_fail(
            db, job.id, "w1", error_code="scanner_failed", error_message="x", retryable=True
        ) == "failed"
        final = db.get(ScanJob, job.id)
        db.refresh(final)
        assert final.status == "failed" and final.error_code == "scanner_failed"


def test_non_retryable_failure_is_not_retried(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        assert jobs.retry_or_fail(
            db, job.id, "w1", error_code="timeout", error_message="x", retryable=False
        ) == "failed"


def test_backoff_is_exponential_and_capped(job_env, monkeypatch):
    monkeypatch.setattr(job_env, "scan_job_retry_backoff_seconds", 5.0)
    assert [jobs.backoff_seconds(n) for n in (1, 2, 3)] == [5, 10, 20]
    assert jobs.backoff_seconds(30) == jobs.MAX_RETRY_BACKOFF_SECONDS


def test_expired_lease_is_requeued_then_failed_when_exhausted(
    job_session_factory, job_env, monkeypatch
):
    monkeypatch.setattr(job_env, "scan_job_max_attempts", 2)
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        # A live lease is left alone.
        assert jobs.recover(db) == []
        expire_lease(db, job.id)
        assert jobs.recover(db) == [(job.id, "requeued")]
        assert jobs.claim_next(db, "w2").attempts == 2
        expire_lease(db, job.id)
        assert jobs.recover(db) == [(job.id, "failed")]
        final = db.get(ScanJob, job.id)
        db.refresh(final)
        assert final.status == "failed" and final.error_code == "lease_expired"
        assert event_types(db, job.id).count("recovered") == 2


def test_recovery_honours_a_cancel_requested_before_the_crash(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        jobs.request_cancel(db, job.id)
        expire_lease(db, job.id)
        assert jobs.recover(db) == [(job.id, "cancelled")]


def test_startup_recovery_is_immediate_for_own_worker_id_and_reaps(job_session_factory):
    reaped = []
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        jobs.set_runner_pid(db, job.id, "w1", 4242)
        # Lease is still valid, but a restarted "w1" cannot still be running it.
        assert jobs.recover(db, owner="other", reaper=reaped.append) == []
        assert jobs.recover(db, owner="w1", reaper=reaped.append) == [(job.id, "requeued")]
        assert reaped == [4242]


def test_expired_job_of_another_worker_is_not_reaped_locally(job_session_factory):
    reaped = []
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        jobs.set_runner_pid(db, job.id, "w1", 4242)
        expire_lease(db, job.id)
        # Its pid belongs to another container's namespace; never signal it.
        assert jobs.recover(db, owner="w2", reaper=reaped.append) == [(job.id, "requeued")]
        assert reaped == []


def test_worker_that_lost_its_lease_cannot_overwrite_state(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        expire_lease(db, job.id)
        jobs.recover(db)
        assert jobs.claim_next(db, "w2").lease_owner == "w2"
        assert jobs.heartbeat(db, job.id, "w1") == "lost"
        assert not jobs.finish(db, job.id, "w1", JobStatus.SUCCEEDED)
        assert jobs.retry_or_fail(
            db, job.id, "w1", error_code="x", error_message="x", retryable=True
        ) == "lost"
        current = db.get(ScanJob, job.id)
        db.refresh(current)
        assert current.status == "running" and current.lease_owner == "w2"


def test_release_for_shutdown_does_not_consume_an_attempt(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        assert jobs.release_for_shutdown(db, job.id, "w1")
        again = jobs.claim_next(db, "w2")
        assert again.attempts == 1


def test_event_log_is_bounded_but_lifecycle_events_are_kept(
    job_session_factory, monkeypatch
):
    monkeypatch.setattr(jobs, "MAX_EVENTS_PER_JOB", 4)
    with job_session_factory() as db:
        job = make_job(db)
        jobs.claim_next(db, "w1")
        for i in range(20):
            jobs.record_event(db, job.id, "log", f"line {i}")
        assert jobs.finish(db, job.id, "w1", JobStatus.SUCCEEDED)
        total = db.query(JobEvent).filter(JobEvent.job_id == job.id).count()
        assert total == 5  # 4 up to the cap + the forced terminal event
        assert event_types(db, job.id)[-1] == "succeeded"


def test_deleting_a_job_cascades_events(job_session_factory):
    with job_session_factory() as db:
        job = make_job(db)
        db.delete(db.get(ScanJob, job.id))
        db.commit()
        assert db.query(JobEvent).count() == 0
