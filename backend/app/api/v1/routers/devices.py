# backend/app/api/v1/routers/devices.py
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .... import models, schemas
from ....dependencies import get_db
from ....security import require_api_key

router = APIRouter(prefix="/devices", tags=["devices"])

API_KEY_DEP = [Depends(require_api_key)]
DbDep = Annotated[Session, Depends(get_db)]


def to_schema(m: models.Device) -> schemas.DeviceRead:
    return schemas.DeviceRead(
        id=m.id,
        hostname=m.hostname,
        ip=(m.ip or {}).get("v", []),
        mac=m.mac,
        first_seen=m.first_seen,
        last_seen=m.last_seen,
        discovery_method=m.discovery_method,  # type: ignore[assignment]
        vendor=m.vendor,
        model=m.model,
        os=m.os,
        serial=m.serial,
        location=m.location,
        roles=(m.roles or {}).get("v", []),
        ports=(m.ports or {}).get("v", []),
        snmp=m.snmp,
        api=m.api,
        notes=m.notes,
    )


@router.get("", response_model=list[schemas.DeviceRead])
def list_devices(
    db: DbDep,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: str | None = Query(None),
):
    stmt = db.query(models.Device)
    if q:
        stmt = stmt.filter(models.Device.hostname.like(f"%{q}%"))
    stmt = stmt.order_by(models.Device.hostname).limit(limit).offset(offset)
    return [to_schema(x) for x in stmt.all()]


@router.post("", response_model=schemas.DeviceRead, dependencies=API_KEY_DEP)
def create_device(payload: schemas.DeviceCreate, db: DbDep):
    dev = models.Device(
        id=schemas.new_id(),
        hostname=payload.hostname,
        ip={"v": payload.ip},
        mac=payload.mac,
        first_seen=payload.first_seen,
        last_seen=payload.last_seen,
        discovery_method=payload.discovery_method,
        vendor=payload.vendor,
        model=payload.model,
        os=payload.os,
        serial=payload.serial,
        location=payload.location,
        roles={"v": payload.roles},
        ports={"v": [p.model_dump() for p in payload.ports]},
        snmp=payload.snmp.model_dump() if payload.snmp else None,
        api=payload.api.model_dump() if payload.api else None,
        notes=payload.notes,
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)
    return to_schema(dev)


@router.get("/{device_id}", response_model=schemas.DeviceRead)
def get_device(device_id: str, db: DbDep):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Not found")
    return to_schema(dev)


@router.put(
    "/{device_id}",
    response_model=schemas.DeviceRead,
    dependencies=API_KEY_DEP,
)
def replace_device(device_id: str, payload: schemas.DeviceCreate, db: DbDep):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Not found")
    for k, v in payload.model_dump().items():
        if k in {"roles", "ports", "ip"} and v is not None:
            if k == "roles":
                dev.roles = {"v": v}
            elif k == "ports":
                dev.ports = {"v": [p.model_dump() for p in v]}
            elif k == "ip":
                dev.ip = {"v": v}
        else:
            setattr(dev, k, v)
    db.commit()
    db.refresh(dev)
    return to_schema(dev)


@router.patch(
    "/{device_id}",
    response_model=schemas.DeviceRead,
    dependencies=API_KEY_DEP,
)
def update_device(device_id: str, payload: schemas.DeviceUpdate, db: DbDep):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Not found")
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        if k in {"roles", "ports", "ip"}:
            if k == "roles" and v is not None:
                dev.roles = {"v": v}
            elif k == "ports" and v is not None:
                dev.ports = {"v": [p.model_dump() for p in v]}
            elif k == "ip" and v is not None:
                dev.ip = {"v": v}
        else:
            setattr(dev, k, v)
    db.commit()
    db.refresh(dev)
    return to_schema(dev)


@router.delete(
    "/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=API_KEY_DEP,
)
def delete_device(device_id: str, db: DbDep):
    dev = db.get(models.Device, device_id)
    if dev:
        db.delete(dev)
        db.commit()
    return None
