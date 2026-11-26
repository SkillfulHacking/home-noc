"""Read-only device health API (M19, issue #22). Session required."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ....dependencies import get_db
from ....health import FRESH_SECONDS, STATUSES_ALL, load_sources
from ....models import Device, DeviceHealth, HealthSnapshot
from ....security import require_session

router = APIRouter(tags=["health"], dependencies=[Depends(require_session)])
DbDep = Annotated[Session, Depends(get_db)]


def _iso(value):
    return value.isoformat() if value else None


def _item(device: Device, row: DeviceHealth | None) -> dict:
    sources = load_sources(row.sources) if row else {}
    return {
        "device_id": device.id, "hostname": device.hostname,
        "status": row.status if row else "unknown",
        "reason": row.reason if row else "never observed",
        "last_success_at": _iso(row.last_success_at) if row else None,
        "last_attempt_at": _iso(row.last_attempt_at) if row else None,
        "status_changed_at": _iso(row.status_changed_at) if row else None,
        # Inventory freshness (last_seen) is reported separately from health status.
        "last_seen": _iso(device.last_seen),
        "sources": {n: {"last_success": _iso(s.last_success), "last_attempt": _iso(s.last_attempt),
                        "consecutive_failures": s.failures} for n, s in sources.items()},
    }


@router.get("/health/devices")
def list_health(
    db: DbDep,
    status_filter: Annotated[
        Literal["online", "degraded", "offline", "unknown"] | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """Per-device health plus summary counts over *all* devices (no row = unknown)."""
    counts = dict.fromkeys(STATUSES_ALL, 0)
    for state, n in db.execute(select(DeviceHealth.status, func.count()).group_by(
            DeviceHealth.status)):
        counts[state] = counts.get(state, 0) + n
    total = db.scalar(select(func.count(Device.id))) or 0
    counts["unknown"] += max(total - sum(counts.values()), 0)
    stmt = select(Device, DeviceHealth).outerjoin(DeviceHealth, DeviceHealth.device_id == Device.id)
    if status_filter == "unknown":
        stmt = stmt.where((DeviceHealth.status == "unknown") | (DeviceHealth.device_id.is_(None)))
    elif status_filter:
        stmt = stmt.where(DeviceHealth.status == status_filter)
    rows = db.execute(stmt.order_by(Device.hostname, Device.id).offset(offset).limit(limit)).all()
    return {"summary": {"total": total, **counts}, "freshness_seconds": FRESH_SECONDS,
            "devices": [_item(d, h) for d, h in rows]}


@router.get("/devices/{device_id}/health")
def device_health(device_id: Annotated[str, Path(min_length=1, max_length=36)], db: DbDep,
                  history: Annotated[int, Query(ge=0, le=500)] = 50) -> dict:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    snaps = db.scalars(select(HealthSnapshot).where(HealthSnapshot.device_id == device_id)
                       .order_by(HealthSnapshot.at.desc()).limit(history)).all()
    return {**_item(device, db.get(DeviceHealth, device_id)),
            "snapshots": [{"at": _iso(s.at), "status": s.status, "reason": s.reason}
                          for s in snaps]}
