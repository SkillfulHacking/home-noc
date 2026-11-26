"""Findings API (M18, issue #21). Session required; suppress/unsuppress also need CSRF (POST).

Responses contain only the sanitized, stored fields -- never raw requests/responses."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from ....dependencies import get_db
from ....findings import SEVERITIES, STATUSES, set_suppressed
from ....models import Finding, FindingEvent
from ....security import require_session

router = APIRouter(prefix="/findings", tags=["findings"], dependencies=[Depends(require_session)])
DbDep = Annotated[Session, Depends(get_db)]
FindingId = Annotated[str, Path(min_length=1, max_length=36)]
_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


class SuppressBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=300)


def _iso(value):
    return value.isoformat() if value else None


def _view(f: Finding) -> dict:
    return {
        "id": f.id, "device_id": f.device_id, "template_id": f.template_id, "name": f.name,
        "severity": f.severity, "status": f.status, "host": f.host, "port": f.port,
        "scheme": f.scheme, "path": f.path, "matcher_name": f.matcher_name,
        "first_seen": _iso(f.first_seen), "last_seen": _iso(f.last_seen),
        "resolved_at": _iso(f.resolved_at), "suppressed_reason": f.suppressed_reason,
        "occurrences": f.occurrences, "last_job_id": f.last_job_id,
        "template_version": f.template_version, "scanner_version": f.scanner_version,
        "details": f.details,
    }


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("")
def list_findings(
    db: DbDep,
    device_id: Annotated[str | None, Query(max_length=36)] = None,
    severity: Literal["info", "low", "medium", "high", "critical", "unknown"] | None = None,
    status_filter: Annotated[Literal["open", "resolved", "suppressed"] | None,
                             Query(alias="status")] = None,
    template_id: Annotated[str | None, Query(max_length=128)] = None,
    since: datetime | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100000)] = 0,
) -> dict:
    conds = []
    if device_id:
        conds.append(Finding.device_id == device_id)
    if severity:
        conds.append(Finding.severity == severity)
    if status_filter:
        conds.append(Finding.status == status_filter)
    if template_id:
        conds.append(Finding.template_id == template_id)
    if since:
        conds.append(Finding.last_seen >= (since if since.tzinfo else since.replace(tzinfo=UTC)))
    if q:
        conds.append(or_(Finding.name.ilike(_like(q), escape="\\"),
                         Finding.template_id.ilike(_like(q), escape="\\")))
    total = db.scalar(select(func.count(Finding.id)).where(*conds)) or 0
    counts = dict(db.execute(select(Finding.status, func.count()).where(*conds)
                             .group_by(Finding.status)).all())
    rank = case(_SEVERITY_ORDER, value=Finding.severity, else_=0)
    rows = db.scalars(select(Finding).where(*conds).order_by(
        rank.desc(), Finding.last_seen.desc(), Finding.id).limit(limit).offset(offset)).all()
    return {"total": total, "by_status": {s: counts.get(s, 0) for s in STATUSES},
            "severities": list(SEVERITIES), "findings": [_view(f) for f in rows]}


def _get(db: Session, finding_id: str) -> Finding:
    row = db.get(Finding, finding_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    return row


@router.get("/{finding_id}")
def read_finding(finding_id: FindingId, db: DbDep) -> dict:
    row = _get(db, finding_id)
    trail = db.scalars(select(FindingEvent).where(FindingEvent.finding_id == finding_id)
                       .order_by(FindingEvent.at.desc(), FindingEvent.id.desc()).limit(100)).all()
    return {**_view(row), "history": [
        {"at": _iso(e.at), "type": e.type, "job_id": e.job_id, "actor": e.actor, "note": e.note}
        for e in trail]}


@router.post("/{finding_id}/suppress")
def suppress(finding_id: FindingId, body: SuppressBody, db: DbDep,
             session=Depends(require_session)) -> dict:
    row = set_suppressed(db, _get(db, finding_id), True, session.username, body.reason)
    db.commit()
    return _view(row)


@router.post("/{finding_id}/unsuppress")
def unsuppress(finding_id: FindingId, db: DbDep, session=Depends(require_session)) -> dict:
    row = set_suppressed(db, _get(db, finding_id), False, session.username)
    db.commit()
    return _view(row)
