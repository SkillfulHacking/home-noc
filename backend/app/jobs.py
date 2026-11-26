"""Durable job queue on SQLite (M09, issue #12).

No Redis: jobs are rows, workers poll, and ownership is a time-limited
*lease*. Every state transition is a single guarded ``UPDATE`` so concurrent
workers (or a worker and the API) can never both win:

    queued -> running -> succeeded | failed | cancelled
                 |  \\-> cancelling -> cancelled
                 \\-> queued (retry with backoff / recovery / clean shutdown)

Worker-side writes are additionally conditioned on ``lease_owner``, so a
worker that lost its lease (e.g. it stalled and recovery took the job) cannot
overwrite the new owner's state.
"""
from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.orm import Session, aliased

from .config import settings
from .models import JobEvent, ScanJob

logger = logging.getLogger("home_noc.jobs")

MAX_EVENTS_PER_JOB = 500
MAX_RETRY_BACKOFF_SECONDS = 300.0


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_STATES = (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.CANCELLING)
RUNNING_STATES = (JobStatus.RUNNING, JobStatus.CANCELLING)
TERMINAL_STATES = (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED)


class QueueFull(Exception):
    """Too many queued/running jobs."""


def _now() -> datetime:
    return datetime.now(UTC)


def _lease_until(now: datetime) -> datetime:
    return now + timedelta(seconds=settings.worker_lease_seconds)


def backoff_seconds(attempts: int) -> float:
    """Exponential backoff after ``attempts`` failed attempts, bounded."""
    base = settings.scan_job_retry_backoff_seconds
    return min(base * (2 ** max(attempts - 1, 0)), MAX_RETRY_BACKOFF_SECONDS)


# ---------------------------------------------------------------- events

def _add_event(
    db: Session, job_id: str, type_: str, message: str, *,
    level: str = "info", data: dict | None = None, force: bool = False,
) -> None:
    """Stage an event (caller commits). Non-forced events are dropped once a
    job has ``MAX_EVENTS_PER_JOB`` rows, so a chatty job cannot grow the
    database without bound; lifecycle events are always kept."""
    if not force:
        count = db.scalar(select(func.count(JobEvent.id)).where(JobEvent.job_id == job_id))
        if (count or 0) >= MAX_EVENTS_PER_JOB:
            return
    db.add(JobEvent(
        job_id=job_id, created_at=_now(), level=level, type=type_[:32],
        message=message[:512], data=data,
    ))


def record_event(
    db: Session, job_id: str, type_: str, message: str, *,
    level: str = "info", data: dict | None = None,
) -> None:
    _add_event(db, job_id, type_, message, level=level, data=data)
    db.commit()


def list_events(db: Session, job_id: str, after: int = 0, limit: int = 100) -> list[JobEvent]:
    stmt = (
        select(JobEvent)
        .where(JobEvent.job_id == job_id, JobEvent.id > after)
        .order_by(JobEvent.id)
        .limit(limit)
    )
    return list(db.scalars(stmt))


# ------------------------------------------------------------ API side

_enqueue_lock = threading.Lock()


def enqueue_scan(
    db: Session, *, profile: str, targets: list[str], progress_total: int, created_by: str,
    kind: str = "scan", commit: bool = True, targets_extra: dict | None = None,
) -> ScanJob:
    """Create a queued job. Scan ``targets`` must already be scope-validated.

    ``commit=False`` lets a caller (the scheduler) make the enqueue atomic with
    its own state change; the caller then owns the commit."""
    with _enqueue_lock:  # the API runs one process; this closes the check/insert race
        active = db.scalar(
            select(func.count(ScanJob.id)).where(ScanJob.status.in_(ACTIVE_STATES))
        )
        if (active or 0) >= settings.scan_max_active_jobs:
            raise QueueFull
        now = _now()
        job = ScanJob(
            id=str(uuid.uuid4()), kind=kind, profile=profile,
            targets={"v": targets, **(targets_extra or {})},
            status=JobStatus.QUEUED.value, created_by=created_by[:255],
            created_at=now, updated_at=now, available_at=now,
            attempts=0, max_attempts=settings.scan_job_max_attempts,
            cancel_requested=False, progress_total=progress_total, progress_done=0,
        )
        db.add(job)
        # Persist the parent before inserting its FK-linked events.
        db.flush()
        _add_event(db, job.id, "queued", "Job queued", force=True)
        if commit:
            db.commit()
    if commit:
        db.refresh(job)
    return job


def request_cancel(db: Session, job_id: str) -> ScanJob | None:
    """Cancel a job. Queued jobs end immediately; running jobs are flagged and
    the owning worker kills the scanner process group on its next heartbeat.
    Returns ``None`` for an unknown job; callers inspect ``status`` otherwise."""
    now = _now()
    res = db.execute(
        update(ScanJob)
        .where(ScanJob.id == job_id, ScanJob.status == JobStatus.QUEUED.value)
        .values(
            status=JobStatus.CANCELLED.value, cancel_requested=True,
            finished_at=now, updated_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    if res.rowcount == 1:
        _add_event(db, job_id, "cancelled", "Cancelled before it started", force=True)
    else:
        res = db.execute(
            update(ScanJob)
            .where(ScanJob.id == job_id, ScanJob.status == JobStatus.RUNNING.value)
            .values(
                status=JobStatus.CANCELLING.value, cancel_requested=True, updated_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        if res.rowcount == 1:
            _add_event(db, job_id, "cancel_requested", "Cancellation requested", force=True)
    db.commit()
    return db.scalar(
        select(ScanJob).where(ScanJob.id == job_id).execution_options(populate_existing=True)
    )


def fail_unauthorized_queued(db: Session, policy) -> list[str]:
    """Fail queued jobs that ``policy`` no longer authorizes (M08A).

    Runs inside the caller's transaction (it never commits) so a policy change,
    its audit row and the jobs it revokes become visible together. The guard on
    ``status == queued`` means a job a worker has just claimed is left to the
    worker, which re-authorizes it before probing. Returns the failed job ids.
    """
    from .scan_scope import ScanProfile, ScopeError, check_profile_enabled, resolve_targets

    failed: list[str] = []
    now = _now()
    queued = list(db.scalars(select(ScanJob).where(ScanJob.status == JobStatus.QUEUED.value)))
    for job in queued:
        try:
            profile = ScanProfile(job.profile)
            check_profile_enabled(profile)
            resolve_targets(list((job.targets or {}).get("v", [])), profile, policy)
            continue
        except (ScopeError, ValueError):
            pass
        res = db.execute(
            update(ScanJob)
            .where(ScanJob.id == job.id, ScanJob.status == JobStatus.QUEUED.value)
            .values(
                status=JobStatus.FAILED.value, finished_at=now, updated_at=now,
                error_code="authorization_revoked",
                error_message="Scan policy no longer authorizes this scan; it was not run",
                **_clear_lease(),
            )
            .execution_options(synchronize_session=False)
        )
        if res.rowcount == 1:
            _add_event(
                db, job.id, "failed", "Job failed: authorization revoked before it started",
                level="error", force=True, data={"error_code": "authorization_revoked"},
            )
            failed.append(job.id)
    return failed


# ----------------------------------------------------------- worker side

def claim_next(db: Session, worker_id: str) -> ScanJob | None:
    """Atomically lease the oldest runnable job, honouring the global cap.

    The cap check lives inside the claiming ``UPDATE`` so two workers racing
    cannot both pass it.
    """
    now = _now()
    running = aliased(ScanJob)
    in_flight = (
        select(func.count(running.id))
        .where(running.status.in_(RUNNING_STATES), running.lease_expires_at > now)
        .scalar_subquery()
    )
    candidates = list(db.scalars(
        select(ScanJob.id)
        .where(ScanJob.status == JobStatus.QUEUED.value, ScanJob.available_at <= now)
        .order_by(ScanJob.available_at, ScanJob.created_at)
        .limit(5)
    ))
    for job_id in candidates:
        res = db.execute(
            update(ScanJob)
            .where(
                ScanJob.id == job_id,
                ScanJob.status == JobStatus.QUEUED.value,
                in_flight < settings.worker_max_concurrent_jobs,
            )
            .values(
                status=JobStatus.RUNNING.value, lease_owner=worker_id,
                lease_expires_at=_lease_until(now), started_at=now, finished_at=None,
                attempts=ScanJob.attempts + 1, runner_pid=None, updated_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        if res.rowcount == 1:
            _add_event(db, job_id, "started", "Job started", force=True)
            db.commit()
            return db.scalar(
                select(ScanJob).where(ScanJob.id == job_id)
                .execution_options(populate_existing=True)
            )
        db.rollback()
    return None


def _owned(job_id: str, worker_id: str):
    return (
        ScanJob.id == job_id,
        ScanJob.lease_owner == worker_id,
        ScanJob.status.in_(RUNNING_STATES),
    )


def heartbeat(db: Session, job_id: str, worker_id: str) -> str:
    """Renew the lease. Returns ``"ok"``, ``"cancel"`` or ``"lost"``."""
    now = _now()
    res = db.execute(
        update(ScanJob).where(*_owned(job_id, worker_id))
        .values(lease_expires_at=_lease_until(now), updated_at=now)
        .execution_options(synchronize_session=False)
    )
    db.commit()
    if res.rowcount != 1:
        return "lost"
    cancel = db.scalar(select(ScanJob.cancel_requested).where(ScanJob.id == job_id))
    return "cancel" if cancel else "ok"


def set_runner_pid(db: Session, job_id: str, worker_id: str, pid: int | None) -> None:
    db.execute(
        update(ScanJob).where(*_owned(job_id, worker_id)).values(runner_pid=pid)
        .execution_options(synchronize_session=False)
    )
    db.commit()


def update_progress(
    db: Session, job_id: str, worker_id: str, done: int, total: int | None = None,
) -> None:
    values: dict = {"progress_done": done, "updated_at": _now()}
    if total is not None:
        values["progress_total"] = total
    db.execute(
        update(ScanJob).where(*_owned(job_id, worker_id)).values(**values)
        .execution_options(synchronize_session=False)
    )
    db.commit()


def _clear_lease() -> dict:
    return {"lease_owner": None, "lease_expires_at": None, "runner_pid": None}


def finish(
    db: Session, job_id: str, worker_id: str, status: JobStatus, *,
    error_code: str | None = None, error_message: str | None = None,
    result: dict | None = None,
    before_commit: Callable[[Session], None] | None = None,
) -> bool:
    """Move an owned job to a terminal state. ``False`` if the lease was lost."""
    if status not in TERMINAL_STATES:
        raise ValueError("Invalid terminal job status")
    now = _now()
    values = dict(
        status=status.value, finished_at=now, updated_at=now,
        error_code=error_code, error_message=(error_message or None) and error_message[:512],
        **_clear_lease(),
    )
    if result is not None:
        values["result"] = result
    res = db.execute(
        update(ScanJob).where(*_owned(job_id, worker_id)).values(**values)
        .execution_options(synchronize_session=False)
    )
    if res.rowcount != 1:
        db.rollback()
        return False
    if before_commit is not None:
        before_commit(db)
        if result is not None:
            # The first UPDATE serialized result before the callback enriched it.
            # Refresh the JSON within the same guarded transaction.
            db.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id, ScanJob.status == status.value)
                .values(result=result)
                .execution_options(synchronize_session=False)
            )
    level = {"succeeded": "info", "cancelled": "warn", "failed": "error"}[status.value]
    message = {
        "succeeded": "Job completed",
        "cancelled": "Job cancelled; scanner stopped",
        "failed": f"Job failed: {error_message or error_code or 'error'}",
    }[status.value]
    _add_event(db, job_id, status.value, message, level=level, force=True,
               data={"error_code": error_code} if error_code else None)
    db.commit()
    return True


def _requeue_values(now: datetime, delay: float) -> dict:
    return dict(
        status=JobStatus.QUEUED.value, available_at=now + timedelta(seconds=delay),
        updated_at=now, **_clear_lease(),
    )


def retry_or_fail(
    db: Session, job_id: str, worker_id: str, *,
    error_code: str, error_message: str, retryable: bool,
) -> str:
    """Schedule a bounded retry with backoff, or fail. Returns the new status
    (``"queued"``/``"failed"``) or ``"lost"``."""
    job = db.scalar(select(ScanJob).where(*_owned(job_id, worker_id))
                    .execution_options(populate_existing=True))
    if job is None:
        return "lost"
    if retryable and not job.cancel_requested and job.attempts < job.max_attempts:
        delay = backoff_seconds(job.attempts)
        now = _now()
        res = db.execute(
            update(ScanJob).where(*_owned(job_id, worker_id))
            .values(error_code=error_code, error_message=error_message[:512],
                    **_requeue_values(now, delay))
            .execution_options(synchronize_session=False)
        )
        if res.rowcount != 1:
            db.rollback()
            return "lost"
        _add_event(
            db, job_id, "retry_scheduled",
            f"Attempt {job.attempts}/{job.max_attempts} failed ({error_code}); "
            f"retrying in {delay:.0f}s",
            level="warn", force=True, data={"error_code": error_code},
        )
        db.commit()
        return JobStatus.QUEUED.value
    ok = finish(db, job_id, worker_id, JobStatus.FAILED,
                error_code=error_code, error_message=error_message)
    return JobStatus.FAILED.value if ok else "lost"


def release_for_shutdown(db: Session, job_id: str, worker_id: str) -> bool:
    """Hand a job back to the queue on clean worker shutdown, without
    consuming an attempt."""
    now = _now()
    res = db.execute(
        update(ScanJob).where(*_owned(job_id, worker_id))
        .values(
            attempts=case((ScanJob.attempts > 0, ScanJob.attempts - 1), else_=0),
            progress_done=0, **_requeue_values(now, 0),
        )
        .execution_options(synchronize_session=False)
    )
    if res.rowcount != 1:
        db.rollback()
        return False
    _add_event(db, job_id, "requeued", "Worker shutting down; job requeued",
               level="warn", force=True)
    db.commit()
    return True


def recover(
    db: Session, *, owner: str | None = None,
    reaper: Callable[[int | None], bool] | None = None,
) -> list[tuple[str, str]]:
    """Resolve jobs whose worker vanished. Returns ``(job_id, outcome)`` pairs.

    A job is abandoned when its lease expired, or -- at worker startup, with
    ``owner`` set -- when it is still leased to this very worker id (a fresh
    process cannot be running it). Outcomes: ``cancelled`` (cancel was already
    requested), ``failed`` (attempts exhausted), ``requeued``.

    The leftover scanner is only reaped for jobs owned by *this* worker id:
    a pid from another container's namespace means nothing here.
    """
    now = _now()
    stale = or_(ScanJob.lease_expires_at < now, ScanJob.lease_expires_at.is_(None))
    if owner is not None:
        stale = or_(stale, ScanJob.lease_owner == owner)
    jobs = list(db.scalars(
        select(ScanJob).where(ScanJob.status.in_(RUNNING_STATES), stale)
    ))
    outcomes: list[tuple[str, str]] = []
    for job in jobs:
        job_id, prev_owner, pid = job.id, job.lease_owner, job.runner_pid
        expiry = job.lease_expires_at
        guard = [
            ScanJob.id == job_id,
            ScanJob.status.in_(RUNNING_STATES),
            ScanJob.lease_owner == prev_owner,
            ScanJob.lease_expires_at.is_(None) if expiry is None
            else ScanJob.lease_expires_at == expiry,
        ]
        if job.cancel_requested:
            outcome, values = "cancelled", dict(
                status=JobStatus.CANCELLED.value, finished_at=now, updated_at=now,
                **_clear_lease())
            message, level = "Worker lost; job cancelled as requested", "warn"
        elif job.attempts >= job.max_attempts:
            outcome, values = "failed", dict(
                status=JobStatus.FAILED.value, finished_at=now, updated_at=now,
                error_code="lease_expired",
                error_message="Worker stopped responding and attempts are exhausted",
                **_clear_lease())
            message, level = "Worker lost and attempts exhausted; job failed", "error"
        else:
            outcome = "requeued"
            values = dict(error_code="lease_expired",
                          error_message="Worker stopped responding; job requeued",
                          **_requeue_values(now, backoff_seconds(job.attempts)))
            message, level = "Worker lost; job requeued for recovery", "warn"
        res = db.execute(update(ScanJob).where(*guard).values(**values)
                         .execution_options(synchronize_session=False))
        if res.rowcount != 1:  # someone else (or a heartbeat) got there first
            db.rollback()
            continue
        _add_event(db, job_id, "recovered", message, level=level, force=True)
        db.commit()
        if reaper is not None and owner is not None and prev_owner == owner:
            reaper(pid)
        outcomes.append((job_id, outcome))
    return outcomes
