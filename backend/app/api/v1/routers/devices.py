# backend/app/api/v1/routers/devices.py
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List

from ....dependencies import get_db
from ....security import require_api_key
from .... import models, schemas

router = APIRouter(prefix="/devices", tags=["devices"])

@router.get("", response_model=List[schemas.DeviceRead])
def list_devices(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: str | None = None,
):
    query = db.query(models.Device)
    if q:
        query = query.filter(models.Device.hostname.ilike(f"%{q}%"))
    rows = query.offset(offset).limit(limit).all()
    # map JSON columns back to lists
    return [to_schema(row) for row in rows]

@router.post("", response_model=schemas.DeviceRead, dependencies=[Depends(require_api_key)])
def create_device(payload: schemas.DeviceCreate, db: Session = Depends(get_db)):
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
        snmp=(payload.snmp.model_dump() if payload.snmp else None),
        api=(payload.api.model_dump() if payload.api else None),
        notes=payload.notes,
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)
    return to_schema(dev)

@router.get("/{device_id}", response_model=schemas.DeviceRead)
def get_device(device_id: str, db: Session = Depends(get_db)):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return to_schema(dev)

@router.put("/{device_id}", response_model=schemas.DeviceRead, dependencies=[Depends(require_api_key)])
def replace_device(device_id: str, payload: schemas.DeviceCreate, db: Session = Depends(get_db)):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    dev.hostname = payload.hostname
    dev.ip = {"v": payload.ip}
    dev.mac = payload.mac
    dev.first_seen = payload.first_seen
    dev.last_seen = payload.last_seen
    dev.discovery_method = payload.discovery_method
    dev.vendor = payload.vendor
    dev.model = payload.model
    dev.os = payload.os
    dev.serial = payload.serial
    dev.location = payload.location
    dev.roles = {"v": payload.roles}
    dev.ports = {"v": [p.model_dump() for p in payload.ports]}
    dev.snmp = (payload.snmp.model_dump() if payload.snmp else None)
    dev.api = (payload.api.model_dump() if payload.api else None)
    dev.notes = payload.notes
    db.commit()
    db.refresh(dev)
    return to_schema(dev)

@router.patch("/{device_id}", response_model=schemas.DeviceRead, dependencies=[Depends(require_api_key)])
def update_device(device_id: str, payload: schemas.DeviceUpdate, db: Session = Depends(get_db)):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        if field == "ip" and value is not None:
            dev.ip = {"v": value}
        elif field == "roles" and value is not None:
            dev.roles = {"v": value}
        elif field == "ports" and value is not None:
            dev.ports = {"v": [p for p in value]}
        elif field in ("snmp","api") and value is not None:
            setattr(dev, field, value)
        else:
            setattr(dev, field, value)
    db.commit()
    db.refresh(dev)
    return to_schema(dev)

@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_api_key)])
def delete_device(device_id: str, db: Session = Depends(get_db)):
    dev = db.get(models.Device, device_id)
    if dev:
        db.delete(dev)
        db.commit()
    return None

def to_schema(row: models.Device) -> schemas.DeviceRead:
    return schemas.DeviceRead(
        id=row.id,
        hostname=row.hostname,
        ip=(row.ip or {}).get("v", []),
        mac=row.mac,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        discovery_method=row.discovery_method,  # type: ignore
        vendor=row.vendor,
        model=row.model,
        os=row.os,
        serial=row.serial,
        location=row.location,
        roles=(row.roles or {}).get("v", []),  # type: ignore
        ports=[p for p in (row.ports or {}).get("v", [])],
        snmp=row.snmp,
        api=row.api,
        notes=row.notes,
    )
