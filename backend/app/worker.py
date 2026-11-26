"""Scan/poll worker process (M09, issue #12): ``python -m app.worker``.

A separate, unprivileged process that polls ``scan_jobs`` for work. It never
listens on a port. Ownership of a job is a lease renewed by heartbeats; if
this process dies the lease lapses and recovery requeues (or fails) the job.
On SIGTERM/SIGINT it stops every scanner process group and hands its jobs back
to the queue without consuming an attempt.
"""
from __future__ import annotations

import logging
import signal
import socket
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from . import connector_jobs, events, health, jobs, scan_policy, scheduler
from .config import settings
from .db import Base, SessionLocal, engine
from .jobs import JobStatus
from .models import ScanJob
from .reconcile import persist_scan_result
from .scan_runner import (
    JobContext,
    JobStopped,
    RunnerError,
    reap_stale_process_group,
    run_scan,
)

logger = logging.getLogger("home_noc.worker")

HEARTBEAT_FILE = Path("/run/home-noc/worker-heartbeat")

Executor = Callable[[JobContext], dict]
ResultPersister = Callable[[Session, str, dict], None]


def default_worker_id() -> str:
    # Stable across restarts of the same container, so a restarted worker can
    # immediately recover jobs its previous process was running. Run one
    # worker process per distinct hostname.
    return socket.gethostname()[:100] or "worker"


class Worker:
    def __init__(
        self,
        session_factory: Callable[[], Session] = SessionLocal,
        worker_id: str | None = None,
        executor: Executor = run_scan,
        result_persister: ResultPersister = persist_scan_result,
        clock: Callable[[], datetime] | None = None,
        snmp_transport=None,
        unifi_http_factory=None,
    ):
        self.session_factory = session_factory
        self.worker_id = worker_id or default_worker_id()
        self.executor = executor
        self.result_persister = result_persister
        self.clock = clock or (lambda: datetime.now(UTC))
        self.snmp_transport = snmp_transport
        self.unifi_http_factory = unifi_http_factory
        self.stop_event = threading.Event()
        self._last_sweep = float("-inf")
        self._threads: dict[str, threading.Thread] = {}

    # -- recovery ---------------------------------------------------------

    def recover_on_startup(self) -> list[tuple[str, str]]:
        """Resolve jobs this worker id left running and reap their scanners."""
        with self.session_factory() as db:
            outcomes = jobs.recover(
                db, owner=self.worker_id, reaper=reap_stale_process_group
            )
        for job_id, outcome in outcomes:
            logger.warning("startup recovery: job %s -> %s", job_id, outcome)
        return outcomes

    def recover_expired(self) -> list[tuple[str, str]]:
        with self.session_factory() as db:
            return jobs.recover(db)

    # -- running one job --------------------------------------------------

    def _context(self, job: ScanJob) -> JobContext:
        job_id = job.id
        interval = min(settings.worker_lease_seconds / 3, 1.0)
        state = {"last": time.monotonic(), "ok": time.monotonic()}

        def check() -> None:
            if self.stop_event.is_set():
                raise JobStopped("shutdown")
            now = time.monotonic()
            if now - state["last"] < interval:
                return
            state["last"] = now
            try:
                with self.session_factory() as db:
                    verdict = jobs.heartbeat(db, job_id, self.worker_id)
            except SQLAlchemyError:
                logger.warning("heartbeat failed for job %s", job_id, exc_info=True)
                # Keep going while our lease is still valid; once it could
                # have lapsed another worker may own the job, so stop.
                if now - state["ok"] >= settings.worker_lease_seconds:
                    raise JobStopped("lost") from None
                return
            state["ok"] = now
            if verdict == "lost":
                raise JobStopped("lost")
            if verdict == "cancel":
                raise JobStopped("cancel")

        def progress(done: int, total: int) -> None:
            with self.session_factory() as db:
                jobs.update_progress(db, job_id, self.worker_id, done, total)

        def event(type_: str, message: str) -> None:
            with self.session_factory() as db:
                jobs.record_event(db, job_id, type_, message)

        def set_pid(pid: int | None) -> None:
            with self.session_factory() as db:
                jobs.set_runner_pid(db, job_id, self.worker_id, pid)

        def policy_loader() -> scan_policy.PolicyState:
            # Fresh session every time: never a cached view of authorization.
            with self.session_factory() as db:
                return scan_policy.load_policy(db)

        targets = list((job.targets or {}).get("v", []))
        return JobContext(
            job_id=job_id, profile=job.profile, targets=targets, attempt=job.attempts,
            check=check, progress=progress, event=event, set_pid=set_pid,
            policy_loader=policy_loader, kind=job.kind,
        )

    def _execute(self, ctx: JobContext) -> dict:
        """Dispatch by job kind; all kinds share one queue, lease and worker."""
        if ctx.kind == "snmp_poll":
            return connector_jobs.run_snmp_poll(ctx, self.session_factory, self.snmp_transport)
        if ctx.kind == "unifi_sync":
            return connector_jobs.run_unifi_sync(ctx, self.session_factory,
                                                 self.unifi_http_factory)
        return self.executor(ctx)

    def run_job(self, job: ScanJob) -> None:
        """Run a claimed job to a resting state. Never raises."""
        job_id = job.id
        ctx = self._context(job)
        try:
            try:
                result = self._execute(ctx)
            except JobStopped as stop:
                self._on_stopped(job_id, stop.reason, stop)
            except RunnerError as err:
                with self.session_factory() as db:
                    outcome = jobs.retry_or_fail(
                        db, job_id, self.worker_id, error_code=err.code,
                        error_message=err.message, retryable=err.retryable,
                    )
                logger.info("job %s: %s -> %s", job_id, err.code, outcome)
            except Exception:  # noqa: BLE001 - classify, never leak text
                logger.exception("job %s crashed", job_id)
                with self.session_factory() as db:
                    jobs.retry_or_fail(
                        db, job_id, self.worker_id, error_code="internal_error",
                        error_message="Unexpected worker error (see worker logs)",
                        retryable=True,
                    )
            else:
                with self.session_factory() as db:
                    jobs.finish(
                        db,
                        job_id,
                        self.worker_id,
                        JobStatus.SUCCEEDED,
                        result=result,
                        before_commit=lambda session: self.result_persister(
                            session, job_id, result
                        ),
                    )
        except Exception:  # noqa: BLE001 - e.g. database down; lease expiry recovers it
            logger.exception("job %s: could not record outcome; recovery will resolve it", job_id)

    def _on_stopped(self, job_id: str, reason: str, stop: JobStopped | None = None) -> None:
        with self.session_factory() as db:
            if reason == "revoked":
                # Authorization ended mid-run. Terminal and non-retryable; keep
                # the observations gathered while the job was still authorized.
                partial = stop.partial if stop else None
                unverified = bool(stop) and stop.detail in {
                    "policy_unavailable", "policy_missing", "policy_invalid",
                }
                error_code = "authorization_unverified" if unverified else "authorization_revoked"
                message = (
                    "Scan authorization could not be verified; the job was stopped"
                    if unverified
                    else "Scan policy no longer authorizes this scan; the job was stopped"
                )

                def terminal(persist: bool) -> None:
                    with self.session_factory() as session:
                        jobs.finish(
                            session, job_id, self.worker_id, JobStatus.FAILED,
                            error_code=error_code, error_message=message,
                            result=partial,
                            before_commit=(
                                (lambda s: self.result_persister(s, job_id, partial))
                                if persist and partial else None
                            ),
                        )

                try:
                    terminal(persist=True)
                except Exception:  # noqa: BLE001 - e.g. reconciliation error
                    # The terminal outcome matters more than inventory
                    # reconciliation: record it with the raw partial result and
                    # let the failure be investigated from the logs.
                    logger.exception("job %s: partial result persistence failed", job_id)
                    terminal(persist=False)
                logger.warning("job %s stopped: authorization revoked (%s)", job_id,
                               stop.detail if stop else None)
            elif reason == "cancel":
                jobs.finish(db, job_id, self.worker_id, JobStatus.CANCELLED)
            elif reason == "shutdown":
                jobs.release_for_shutdown(db, job_id, self.worker_id)
            else:
                logger.warning("job %s: lease lost; scanner stopped, not touching state", job_id)

    # -- scheduling -------------------------------------------------------

    def run_next(self) -> str | None:
        """Claim and run one job synchronously (tests / one-shot use)."""
        with self.session_factory() as db:
            job = jobs.claim_next(db, self.worker_id, settings.worker_job_kinds)
        if job is None:
            return None
        self.run_job(job)
        return job.id

    def run_scheduler(self) -> dict:
        """Fire due schedules; a scheduler failure must never stop job processing."""
        try:
            with self.session_factory() as db:
                return scheduler.tick(db, self.clock)
        except Exception:  # noqa: BLE001
            logger.exception("scheduler tick failed")
            return {}

    def run_health_sweep(self, force: bool = False) -> int:
        """Re-derive statuses as freshness windows lapse (throttled to once a minute)."""
        mono = time.monotonic()
        if not force and mono - self._last_sweep < 60:
            return 0
        self._last_sweep = mono
        try:
            with self.session_factory() as db:
                changed = health.sweep(db, self.clock())
                events.prune(db, self.clock())
                db.commit()
                return changed
        except Exception:  # noqa: BLE001 - never stop job processing
            logger.exception("health sweep failed")
            return 0

    def tick(self) -> None:
        self._touch_heartbeat()
        self._threads = {k: t for k, t in self._threads.items() if t.is_alive()}
        self.recover_expired()
        self.run_scheduler()
        self.run_health_sweep()
        while len(self._threads) < settings.worker_max_concurrent_jobs:
            with self.session_factory() as db:
                job = jobs.claim_next(db, self.worker_id, settings.worker_job_kinds)
            if job is None:
                break
            thread = threading.Thread(
                target=self.run_job, args=(job,), name=f"job-{job.id[:8]}", daemon=False
            )
            self._threads[job.id] = thread
            thread.start()

    def serve(self) -> None:
        self.recover_on_startup()
        logger.info("worker %s started (max %d concurrent)", self.worker_id,
                    settings.worker_max_concurrent_jobs)
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - keep polling through transient errors
                logger.exception("worker tick failed")
            self.stop_event.wait(settings.worker_poll_interval_seconds)
        logger.info("worker stopping; waiting for scanners to exit")
        for thread in list(self._threads.values()):
            thread.join(timeout=settings.worker_kill_grace_seconds + 15)

    def stop(self) -> None:
        self.stop_event.set()

    @staticmethod
    def _touch_heartbeat() -> None:
        try:
            HEARTBEAT_FILE.touch()
        except OSError:
            pass


def _wait_for_schema(timeout: float = 120.0) -> bool:
    """The API container applies migrations; wait until its tables exist."""
    needed = {"scan_jobs", "job_events", "scan_policy", "schedules", "device_health", "events"}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if needed.issubset(set(inspect(engine).get_table_names())):
                return True
        except SQLAlchemyError:
            pass
        time.sleep(2)
    return False


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        kinds = settings.worker_job_kinds
    except ValueError as exc:  # fail at startup, not as a "healthy" worker that never claims
        logger.error("invalid configuration: %s", exc)
        return 2
    logger.info("worker job kinds: %s", ",".join(kinds))
    if settings.app_env in {"dev", "test"}:
        from . import models  # noqa: F401
        Base.metadata.create_all(bind=engine)
    if not _wait_for_schema():
        logger.error("database schema is not initialized; is the backend migrating?")
        return 1
    worker = Worker()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: worker.stop())
    worker.serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
