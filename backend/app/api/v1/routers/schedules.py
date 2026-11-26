"""Schedule management API (M16, issue #19). Session + CSRF on every route.

Scan schedules are limited to the non-intrusive discovery and ports profiles and
their targets must already be authorized; they are re-authorized on every
firing (see ``app.scheduler``). Pause/resume is the ``enabled`` flag: resuming
never replays missed runs.
"""
from __future__ import annotations

import random
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ....dependencies import get_db
from ....models import Device, Schedule
from ....scan_scope import ScanProfile, ScopeError, check_profile_enabled, resolve_targets
from ....scheduler import MAX_INTERVAL, MIN_INTERVAL, SCHEDULABLE_PROFILES
from ....security import require_session

router = APIRouter(prefix="/schedules", tags=["schedules"], dependencies=[Depends(require_session)])
ScheduleId = Annotated[str, Path(min_length=1, max_length=36)]
MAX_SCHEDULES = 100
FIRST_RUN_SPREAD_SECONDS = 60


class ScheduleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, pattern=r"^[\w .:@/-]+$")
    kind: Literal["scan", "snmp_poll", "unifi_sync"]
    profile: str | None = None
    targets: list[str] = Field(default_factory=list, max_length=64)
    interval_seconds: int = Field(ge=60, le=MAX_INTERVAL)
    jitter_percent: int = Field(default=10, ge=0, le=25)
    enabled: bool = True


class SchedulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[\w .:@/-]+$")
    targets: list[str] | None = Field(default=None, max_length=64)
    interval_seconds: int | None = Field(default=None, ge=60, le=MAX_INTERVAL)
    jitter_percent: int | None = Field(default=None, ge=0, le=25)
    enabled: bool | None = None


def _view(s: Schedule) -> dict:
    return {
        "id": s.id, "name": s.name, "kind": s.kind, "profile": s.profile,
        "targets": list((s.targets or {}).get("v", [])), "interval_seconds": s.interval_seconds,
        "jitter_percent": s.jitter_percent, "enabled": s.enabled,
        "next_run_at": s.next_run_at, "last_run_at": s.last_run_at, "last_job_id": s.last_job_id,
        "last_error_code": s.last_error_code, "consecutive_failures": s.consecutive_failures,
        "created_by": s.created_by, "created_at": s.created_at, "updated_at": s.updated_at,
    }


def _validate(db: Session, kind: str, profile: str | None, targets: list[str]) -> str | None:
    """Returns the normalized profile; raises HTTPException on invalid/unauthorized input."""
    if kind == "scan":
        profile = profile or ScanProfile.DISCOVERY.value
        if profile not in SCHEDULABLE_PROFILES:
            raise HTTPException(422, detail="Only discovery and ports profiles can be scheduled")
        try:
            check_profile_enabled(ScanProfile(profile))
            resolve_targets(targets, ScanProfile(profile))
        except ScopeError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=exc.message) from None
        return profile
    if profile is not None:
        raise HTTPException(422, detail="profile applies to scan schedules only")
    if kind == "unifi_sync":
        if targets:
            raise HTTPException(422, detail="unifi_sync schedules take no targets")
        return None
    known = set(db.scalars(select(Device.id).where(Device.id.in_(targets)))) if targets else set()
    if set(targets) - known:
        raise HTTPException(422, detail="Unknown device id in targets")
    return None


def _check_interval(kind: str, seconds: int) -> None:
    if seconds < MIN_INTERVAL[kind]:
        raise HTTPException(422, detail=f"interval_seconds must be at least {MIN_INTERVAL[kind]}")


def _first_run(now: datetime, interval: int) -> datetime:
    spread = min(interval, FIRST_RUN_SPREAD_SECONDS)
    return now + timedelta(seconds=random.uniform(0, spread))  # noqa: S311 - jitter only


@router.get("")
def list_schedules(db: Annotated[Session, Depends(get_db)]) -> dict:
    rows = db.scalars(select(Schedule).order_by(Schedule.created_at, Schedule.id)).all()
    return {"schedules": [_view(s) for s in rows]}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_schedule(body: ScheduleIn, db: Annotated[Session, Depends(get_db)],
                    session=Depends(require_session)) -> dict:
    _check_interval(body.kind, body.interval_seconds)
    if len(db.scalars(select(Schedule.id)).all()) >= MAX_SCHEDULES:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Too many schedules")
    profile = _validate(db, body.kind, body.profile, body.targets)
    now = datetime.now(UTC)
    sched = Schedule(
        id=str(uuid.uuid4()), name=body.name, kind=body.kind, profile=profile,
        targets={"v": body.targets}, interval_seconds=body.interval_seconds,
        jitter_percent=body.jitter_percent, enabled=body.enabled,
        next_run_at=_first_run(now, body.interval_seconds), consecutive_failures=0,
        created_by=session.username[:255], created_at=now, updated_at=now,
    )
    db.add(sched)
    db.commit()
    return _view(sched)


def _get(db: Session, schedule_id: str) -> Schedule:
    sched = db.get(Schedule, schedule_id)
    if sched is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    return sched


@router.get("/{schedule_id}")
def read_schedule(schedule_id: ScheduleId, db: Annotated[Session, Depends(get_db)]) -> dict:
    return _view(_get(db, schedule_id))


@router.patch("/{schedule_id}")
def update_schedule(schedule_id: ScheduleId, body: SchedulePatch,
                    db: Annotated[Session, Depends(get_db)]) -> dict:
    sched = _get(db, schedule_id)
    now = datetime.now(UTC)
    changes = body.model_dump(exclude_unset=True)
    if "interval_seconds" in changes:
        _check_interval(sched.kind, changes["interval_seconds"])
    if "targets" in changes:
        _validate(db, sched.kind, sched.profile, changes["targets"])
        sched.targets = {"v": changes["targets"]}
    for key in ("name", "jitter_percent"):
        if changes.get(key) is not None:
            setattr(sched, key, changes[key])
    if "interval_seconds" in changes:
        sched.interval_seconds = changes["interval_seconds"]
        sched.next_run_at = min(sched.next_run_at, now + timedelta(seconds=sched.interval_seconds))
    if changes.get("enabled") is not None and changes["enabled"] != sched.enabled:
        sched.enabled = changes["enabled"]
        if sched.enabled:  # resume: never replay missed runs
            sched.next_run_at = _first_run(now, sched.interval_seconds)
            sched.consecutive_failures = 0
    sched.updated_at = now
    db.commit()
    return _view(sched)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(schedule_id: ScheduleId, db: Annotated[Session, Depends(get_db)]) -> Response:
    db.delete(_get(db, schedule_id))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
