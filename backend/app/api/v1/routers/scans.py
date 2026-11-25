# backend/app/api/v1/routers/scans.py
import ipaddress
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .... import jobs, scan_policy
from ....config import settings
from ....dependencies import get_db
from ....models import ScanJob
from ....scan_scope import (
    PROFILES,
    ScanProfile,
    ScopeError,
    allowed_networks,
    check_profile_enabled,
    log_authorization,
    resolve_targets,
)
from ....security import SessionDep
from .scan_policy import policy_view

router = APIRouter(prefix="/scans", tags=["scans"])

Targets = Annotated[
    list[str],
    Query(..., description="IPv4 addresses or CIDRs inside the authorized scan scope"),
]

_FORBIDDEN_CODES = {
    "out_of_scope", "public_address", "target_forbidden",
    "no_scope_configured", "profile_disabled",
    "private_scanning_disabled", "public_not_allowlisted", "excluded_target",
    "mixed_range", "profile_not_allowed_for_public",
}
# The stored policy could not be trusted or read: deny, and say it is a server condition.
_UNAVAILABLE_CODES = {"policy_unavailable", "policy_missing", "policy_invalid"}


class PreflightRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # no free-form scanner flags

    targets: list[str] = Field(min_length=1, max_length=64)
    profile: ScanProfile = ScanProfile.DISCOVERY


def _preflight(targets: list[str], profile: ScanProfile, session, dry_run: bool) -> dict:
    try:
        check_profile_enabled(profile)
        networks, count = resolve_targets(targets, profile)
    except ScopeError as exc:
        # Log the rejection reason code only; never echo raw operator input.
        log_authorization(
            operator=session.username, profile=profile, networks=[], count=0,
            dry_run=dry_run, outcome=f"rejected:{exc.code}",
        )
        if exc.code in _UNAVAILABLE_CODES:
            status = 503
        else:
            status = 403 if exc.code in _FORBIDDEN_CODES else 422
        raise HTTPException(
            status_code=status, detail={"code": exc.code, "message": exc.message}
        ) from None
    log_authorization(
        operator=session.username, profile=profile, networks=networks, count=count,
        dry_run=dry_run, outcome="approved",
    )
    spec = PROFILES[profile]
    return {
        "approved": True,
        "mode": "dry-run" if dry_run else "exec",
        "profile": profile.value,
        "intrusive": spec.intrusive,
        "resolved_targets": [str(n) for n in networks],
        "resolved_target_count": count,
        "limits": {
            "max_hosts": spec.max_hosts,
            "timeout_seconds": spec.timeout_seconds,
            "max_concurrency": spec.max_concurrency,
        },
    }


@router.get("/scope")
def scope(session: SessionDep):
    """Effective authorization (runtime policy within the deployment ceiling) and
    profiles, for the UI. ``allowed_cidrs`` is the immutable environment ceiling
    (empty when the deployment does not restrict it)."""
    try:
        policy = scan_policy.load_current_policy()
        view = policy_view(policy)
        policy_error = None
    except scan_policy.PolicyUnavailable as exc:
        view, policy_error = None, {"code": exc.code, "message": exc.message}
    return {
        "allowed_cidrs": [str(n) for n in allowed_networks()],
        "allow_public": bool(view and view["effective"]["public_scanning"]),
        "policy": view,
        "policy_error": policy_error,
        "profiles": [
            {
                "name": p.name.value,
                "description": p.description,
                "intrusive": p.intrusive,
                "enabled": (not p.intrusive) or settings.scan_security_profile_enabled,
                "max_hosts": p.max_hosts,
            }
            for p in PROFILES.values()
        ],
    }


@router.post("/preflight")
def preflight(body: PreflightRequest, session: SessionDep):
    """Validate targets/profile against the authorized scope (dry run)."""
    return _preflight(body.targets, body.profile, session, dry_run=True)


@router.post("/ping-sweep")
def ping_sweep(
    targets: Targets,
    session: SessionDep,
    dry_run: bool = True,
):
    """Discovery-profile ping sweep. Scope is validated in every mode."""
    result = _preflight(targets, ScanProfile.DISCOVERY, session, dry_run)
    if dry_run:
        return result
    # Intentionally not executing external commands by default.
    result["executed"] = False
    result["reason"] = "Execution disabled by default"
    return result


# --------------------------------------------------------------- M09 jobs
# The API only records and controls jobs; scanning happens in the separate
# unprivileged worker process. Scope is validated here (fail fast) and again
# by the worker immediately before it runs.

DbDep = Annotated[Session, Depends(get_db)]
JobId = Annotated[str, Path(min_length=1, max_length=36)]


def serialize_job(job: ScanJob) -> dict:
    total = job.progress_total or 0
    done = min(job.progress_done or 0, total) if total else 0
    if job.status == jobs.JobStatus.SUCCEEDED.value:
        percent = 100
    else:
        percent = int(100 * done / total) if total else 0
    # Internal lease/pid fields are deliberately not exposed.
    return {
        "id": job.id,
        "kind": job.kind,
        "profile": job.profile,
        "targets": list((job.targets or {}).get("v", [])),
        "status": job.status,
        "created_by": job.created_by,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "cancel_requested": job.cancel_requested,
        "progress": {"done": done, "total": total, "percent": percent},
        "error_code": job.error_code,
        "error_message": job.error_message,
        "result": job.result,
    }


def _get_job_or_404(db: Session, job_id: str) -> ScanJob:
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.post("/jobs", status_code=202)
def start_job(body: PreflightRequest, auth_session: SessionDep, db: DbDep):
    """Queue a scan for the worker. Same scope rules as preflight."""
    result = _preflight(body.targets, body.profile, auth_session, dry_run=False)
    resolved = result["resolved_targets"]
    try:
        job = jobs.enqueue_scan(
            db,
            profile=body.profile.value,
            targets=resolved,
            progress_total=sum(ipaddress.ip_network(t).num_addresses for t in resolved),
            created_by=auth_session.username,
        )
    except jobs.QueueFull:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "too_many_active_jobs",
                "message": f"At most {settings.scan_max_active_jobs} scan jobs may be "
                           "queued or running; wait for one to finish or cancel it",
            },
        ) from None
    return serialize_job(job)


@router.get("/jobs")
def list_jobs(
    auth_session: SessionDep,
    db: DbDep,
    status: jobs.JobStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
):
    stmt = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    if status is not None:
        stmt = stmt.where(ScanJob.status == status.value)
    return {"items": [serialize_job(j) for j in db.scalars(stmt)]}


@router.get("/jobs/{job_id}")
def get_job(job_id: JobId, auth_session: SessionDep, db: DbDep):
    return serialize_job(_get_job_or_404(db, job_id))


@router.get("/jobs/{job_id}/events")
def get_job_events(
    job_id: JobId,
    auth_session: SessionDep,
    db: DbDep,
    after: Annotated[
        int, Query(ge=0, description="Return events with id greater than this cursor")
    ] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    """Poll for progress events: pass the previous ``next_after`` as ``after``."""
    job = _get_job_or_404(db, job_id)
    events = jobs.list_events(db, job_id, after, limit)
    return {
        "job_id": job_id,
        "status": job.status,
        "terminal": job.status in {s.value for s in jobs.TERMINAL_STATES},
        "next_after": events[-1].id if events else after,
        "events": [
            {
                "id": e.id, "at": e.created_at, "level": e.level, "type": e.type,
                "message": e.message, "data": e.data,
            }
            for e in events
        ],
    }


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: JobId, auth_session: SessionDep, db: DbDep):
    """Cancel a job. Idempotent while cancelling/cancelled; 409 once the job
    has already finished some other way."""
    job = jobs.request_cancel(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status in (jobs.JobStatus.SUCCEEDED.value, jobs.JobStatus.FAILED.value):
        raise HTTPException(
            status_code=409,
            detail={"code": "job_finished", "message": f"Job already {job.status}"},
        )
    return serialize_job(job)
