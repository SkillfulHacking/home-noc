"""Event history API (M20, issue #23). Session required; acknowledge needs CSRF (POST)."""
from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from ....dependencies import get_db
from ....events import SEVERITIES, TYPES
from ....models import Event
from ....security import require_session

router = APIRouter(prefix="/events", tags=["events"], dependencies=[Depends(require_session)])
DbDep = Annotated[Session, Depends(get_db)]
EventType = Literal[TYPES]  # type: ignore[valid-type]
Severity = Literal[SEVERITIES]  # type: ignore[valid-type]


def _view(e: Event) -> dict:
    return {
        "id": e.id, "at": e.at.isoformat(), "last_at": e.last_at.isoformat(), "type": e.type,
        "severity": e.severity, "device_id": e.device_id, "hostname": e.hostname,
        "summary": e.summary, "details": e.details, "count": e.count,
        "acknowledged_at": e.acknowledged_at.isoformat() if e.acknowledged_at else None,
    }


def _encode(e: Event) -> str:
    return base64.urlsafe_b64encode(f"{e.last_at.isoformat()}|{e.id}".encode()).decode()


def _decode(cursor: str) -> tuple[datetime, str]:
    try:
        at, ident = base64.urlsafe_b64decode(cursor.encode()).decode().split("|", 1)
        parsed = datetime.fromisoformat(at)
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)), ident
    except (ValueError, UnicodeError):
        raise HTTPException(422, detail="Invalid cursor") from None


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("")
def list_events(
    db: DbDep,
    type_: Annotated[EventType | None, Query(alias="type")] = None,
    severity: Severity | None = None,
    device_id: Annotated[str | None, Query(max_length=36)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    acknowledged: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> dict:
    """Newest first; keyset-paginated (``next_cursor``), filterable and searchable."""
    conds = []
    if type_:
        conds.append(Event.type == type_)
    if severity:
        conds.append(Event.severity == severity)
    if device_id:
        conds.append(Event.device_id == device_id)
    if since:
        conds.append(Event.last_at >= (since if since.tzinfo else since.replace(tzinfo=UTC)))
    if until:
        conds.append(Event.last_at <= (until if until.tzinfo else until.replace(tzinfo=UTC)))
    if q:
        conds.append(or_(Event.summary.ilike(_like(q), escape="\\"),
                         Event.hostname.ilike(_like(q), escape="\\")))
    if acknowledged is True:
        conds.append(Event.acknowledged_at.is_not(None))
    elif acknowledged is False:
        conds.append(Event.acknowledged_at.is_(None))
    total = db.scalar(select(func.count(Event.id)).where(*conds)) or 0
    page = list(conds)
    if cursor:
        at, ident = _decode(cursor)
        page.append(or_(Event.last_at < at, and_(Event.last_at == at, Event.id < ident)))
    rows = db.scalars(select(Event).where(*page).order_by(Event.last_at.desc(), Event.id.desc())
                      .limit(limit + 1)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    return {"total": total, "events": [_view(e) for e in rows],
            "next_cursor": _encode(rows[-1]) if more and rows else None}


@router.get("/{event_id}")
def read_event(event_id: Annotated[str, Path(min_length=1, max_length=36)], db: DbDep) -> dict:
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    return _view(event)


@router.post("/{event_id}/ack")
def acknowledge(event_id: Annotated[str, Path(min_length=1, max_length=36)], db: DbDep) -> dict:
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    if event.acknowledged_at is None:
        event.acknowledged_at = datetime.now(UTC)
        db.commit()
    return _view(event)
