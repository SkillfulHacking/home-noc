"""Recurring job scheduler (M16, issue #19).

``tick`` is a pure function of (database, clock, rng): the worker calls it with
the wall clock, tests with a fake one. Guarantees:

* **No duplicate runs.** A schedule fires only if a compare-and-set of
  ``next_run_at`` succeeds, in the *same transaction* as the job insert, so a
  crash or a second scheduler cannot enqueue the same run twice.
* **No catch-up storms.** Missed runs (downtime, pause) are skipped; the next run is
  computed from *now*.
* **Fail closed.** Scan targets are re-authorized against the live policy at every
  firing; an unauthorized schedule enqueues nothing and records the reason.
* **Backoff + jitter.** After consecutive failed jobs the interval is multiplied
  (x2 per failure, capped at x8); jitter spreads schedules out.
* **Shared queue and budgets.** Jobs go through ``jobs.enqueue_scan`` (same queue,
  same ``scan_max_active_jobs`` cap as UI-triggered jobs) and at most
  ``scheduler_max_new_jobs_per_tick`` schedules fire per tick.
* Never overlaps: a schedule whose previous job is still queued/running waits.
"""
from __future__ import annotations

import logging
import random
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import jobs, scan_scope
from .config import settings
from .models import ScanJob, Schedule
from .scan_scope import ScanProfile, ScopeError

logger = logging.getLogger("home_noc.scheduler")

MIN_INTERVAL = {"scan": 300, "snmp_poll": 60, "unifi_sync": 60}
MAX_INTERVAL = 7 * 24 * 3600
MAX_BACKOFF_FACTOR = 8
BUSY_RETRY_SECONDS = 60
SCHEDULABLE_PROFILES = {ScanProfile.DISCOVERY.value, ScanProfile.PORTS.value}
Clock = Callable[[], datetime]


def next_run(now: datetime, interval: int, jitter_percent: int, failures: int,
             rng: random.Random) -> datetime:
    """UTC time of the next run: interval * backoff, plus jitter in [0, jitter%]."""
    factor = min(2 ** max(failures, 0), MAX_BACKOFF_FACTOR)
    base = interval * factor
    jitter = base * (jitter_percent / 100) * rng.random()
    return now + timedelta(seconds=base + jitter)


def _previous_job(db: Session, sched: Schedule) -> ScanJob | None:
    return db.get(ScanJob, sched.last_job_id) if sched.last_job_id else None


def _targets_for(sched: Schedule) -> list[str]:
    return list((sched.targets or {}).get("v", []))


def _fire(db: Session, sched: Schedule, now: datetime, rng: random.Random) -> str:
    """Fire one due schedule. Returns an outcome label (for tests/logging)."""
    prev = _previous_job(db, sched)
    if prev is not None and prev.status in jobs.ACTIVE_STATES:
        return "overlap_skipped"

    failures = sched.consecutive_failures
    if prev is not None and prev.finished_at is not None:
        failures = failures + 1 if prev.status == jobs.JobStatus.FAILED.value else 0
    old_next = sched.next_run_at
    new_next = next_run(now, sched.interval_seconds, sched.jitter_percent, failures, rng)

    def claim(error: str | None, job_id: str | None, ran: bool, next_at: datetime) -> bool:
        values = {"next_run_at": next_at, "consecutive_failures": failures,
                  "last_error_code": error, "updated_at": now}
        if ran:
            values.update(last_run_at=now, last_job_id=job_id)
        res = db.execute(update(Schedule).where(
            Schedule.id == sched.id, Schedule.enabled.is_(True),
            Schedule.next_run_at == old_next).values(**values))
        return res.rowcount == 1

    progress_total, targets, profile = 0, [], sched.profile or "connector"
    if sched.kind == "scan":
        if profile not in SCHEDULABLE_PROFILES:  # intrusive profiles never run unattended
            claim("not_schedulable", None, False, new_next)
            db.commit()
            return "rejected:not_schedulable"
        try:
            nets, count = scan_scope.resolve_targets(_targets_for(sched), ScanProfile(profile))
            scan_scope.check_profile_enabled(ScanProfile(profile))
        except (ScopeError, ValueError) as exc:
            code = getattr(exc, "code", "invalid_schedule")[:32]
            claim(code, None, False, new_next)
            db.commit()
            return f"rejected:{code}"
        targets, progress_total = [str(n) for n in nets], count
    else:
        targets = _targets_for(sched)
        progress_total = max(len(targets), 1)

    if not claim(None, None, True, new_next):
        db.rollback()
        return "lost_race"
    try:
        job = jobs.enqueue_scan(
            db, profile=profile, targets=targets, progress_total=progress_total,
            created_by=f"schedule:{sched.id}", kind=sched.kind, commit=False)
    except jobs.QueueFull:
        db.rollback()
        retry = now + timedelta(seconds=BUSY_RETRY_SECONDS)
        claim("queue_full", None, False, retry)
        db.commit()
        return "queue_full"
    db.execute(update(Schedule).where(Schedule.id == sched.id).values(last_job_id=job.id))
    db.commit()
    return "enqueued"


def tick(db: Session, clock: Clock | None = None, rng: random.Random | None = None) -> dict:
    """Fire due schedules (bounded per tick). Returns {schedule_id: outcome}."""
    now = (clock or (lambda: datetime.now(UTC)))()
    rng = rng or random.Random()  # noqa: S311 - jitter only, not security
    due = list(db.scalars(
        select(Schedule).where(Schedule.enabled.is_(True), Schedule.next_run_at <= now)
        .order_by(Schedule.next_run_at, Schedule.id)
        .limit(settings.scheduler_max_new_jobs_per_tick)
    ))
    outcomes: dict[str, str] = {}
    for sched in due:
        try:
            outcomes[sched.id] = _fire(db, sched, now, rng)
        except Exception:  # noqa: BLE001 - one bad schedule must not stop the others
            db.rollback()
            logger.exception("schedule %s failed to fire", sched.id)
            outcomes[sched.id] = "error"
    return outcomes
