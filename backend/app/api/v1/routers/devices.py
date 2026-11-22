# backend/app/api/v1/routers/devices.py
from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, get_args

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .... import models, schemas
from ....dependencies import get_db
from ....security import require_api_key
from ....validators import normalize_ip, normalize_mac

router = APIRouter(prefix="/devices", tags=["devices"])
logger = logging.getLogger(__name__)

API_KEY_DEP = [Depends(require_api_key)]
DbDep = Annotated[Session, Depends(get_db)]

_ALLOWED_ROLES = set(get_args(schemas.Role))
_ALLOWED_DISCOVERY_METHODS = set(get_args(schemas.DiscoveryMethod))


def _commit_or_409(db: Session, detail: str) -> None:
    """Commit, translating a DB-level uniqueness race (two concurrent
    requests both passing the pre-insert conflict check) into a 409 instead
    of letting the IntegrityError surface as an unhandled 500."""
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail) from None


def _sync_mac_identity(db: Session, dev: models.Device) -> None:
    """Keep the device_identities table in sync with Device.mac and enforce
    that a given MAC can only ever belong to one canonical device."""
    existing = (
        db.query(models.DeviceIdentity)
        .filter(models.DeviceIdentity.device_id == dev.id, models.DeviceIdentity.source == "mac")
        .first()
    )
    if not dev.mac:
        if existing:
            db.delete(existing)
        return

    # dev.mac may still hold a pre-migration-0002 legacy form (e.g.
    # "AA-BB-CC-DD-EE-FF") if this PATCH didn't touch the mac field itself,
    # since DeviceUpdate only normalizes fields the caller actually sent.
    # Normalize it here too, so the uniqueness check below always compares
    # against the same canonical form the (source="mac", external_id)
    # constraint expects.
    try:
        dev.mac = normalize_mac(dev.mac)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Stored MAC {dev.mac!r} is invalid; set a valid mac to continue",
        ) from None

    conflict = (
        db.query(models.DeviceIdentity)
        .filter(
            models.DeviceIdentity.source == "mac",
            models.DeviceIdentity.external_id == dev.mac,
            models.DeviceIdentity.device_id != dev.id,
        )
        .first()
    )
    if conflict:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Device with MAC {dev.mac} already exists",
        )

    if existing:
        existing.external_id = dev.mac
    else:
        db.add(
            models.DeviceIdentity(
                id=schemas.new_id(),
                device_id=dev.id,
                source="mac",
                external_id=dev.mac,
            )
        )


def _sanitize_ports(raw_ports: object) -> list[dict]:
    if not isinstance(raw_ports, list):
        return []
    sanitized = []
    for p in raw_ports:
        if not isinstance(p, dict):
            continue
        try:
            sanitized.append(schemas.Port(**p).model_dump())
        except (TypeError, ValidationError):
            continue
    return sanitized


def _sanitize_snmp(raw_snmp: object) -> dict | None:
    if not isinstance(raw_snmp, dict) or not raw_snmp:
        return None
    try:
        return schemas.SNMPInfo(**raw_snmp).model_dump()
    except ValidationError:
        return None


def _sanitize_api(raw_api: object) -> dict | None:
    if not isinstance(raw_api, dict) or not raw_api:
        return None
    try:
        return schemas.APIInfo(**raw_api).model_dump()
    except ValidationError:
        # Most likely cause of the failure is a credential embedded in the
        # url (user:pass@host or a token query param); never fall back to
        # returning that raw value, only ever a value that has already
        # passed APIInfo's own credential checks.
        stripped = {k: v for k, v in raw_api.items() if k in ("type",)}
        try:
            return schemas.APIInfo(**stripped).model_dump()
        except ValidationError:
            return None


def to_schema(m: models.Device) -> schemas.DeviceRead:
    """Build the canonical read model from a stored row.

    Rows written before migration 0002's stricter MAC/IP/port/credential-URL
    validation can still carry non-conforming legacy values. Rather than let
    one bad row 500 the whole inventory listing, quarantine just the
    offending fragments (drop/null them) so the device is still visible and
    an operator can PATCH it to fix the underlying value.
    """
    kwargs = dict(
        id=m.id,
        hostname=m.hostname,
        ip=(m.ip or {}).get("v", []),
        mac=m.mac,
        first_seen=m.first_seen,
        last_seen=m.last_seen,
        discovery_method=m.discovery_method,
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
    try:
        return schemas.DeviceRead(**kwargs)
    except ValidationError:
        logger.warning("Device %s has non-conforming legacy data; sanitizing for read", m.id)
        if kwargs["mac"]:
            try:
                normalize_mac(kwargs["mac"])
            except ValueError:
                kwargs["mac"] = None
        kwargs["ip"] = [ip for ip in kwargs["ip"] if _is_valid_ip(ip)]
        kwargs["roles"] = [r for r in kwargs["roles"] if r in _ALLOWED_ROLES]
        if kwargs["discovery_method"] not in _ALLOWED_DISCOVERY_METHODS:
            kwargs["discovery_method"] = None
        kwargs["ports"] = _sanitize_ports(kwargs["ports"])
        kwargs["snmp"] = _sanitize_snmp(kwargs["snmp"])
        kwargs["api"] = _sanitize_api(kwargs["api"])
        return schemas.DeviceRead(**kwargs)


def _is_valid_ip(value: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        normalize_ip(value)
        return True
    except ValueError:
        return False


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
    db.flush()
    _sync_mac_identity(db, dev)
    _commit_or_409(db, f"Device with MAC {dev.mac} already exists")
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
    # payload.model_dump() already recursively converts nested models (Port,
    # SNMPInfo, APIInfo) into plain dicts, so ports/roles/ip must be assigned
    # as-is rather than re-serialized (previously caused AttributeError).
    for k, v in payload.model_dump().items():
        if k == "roles":
            dev.roles = {"v": v}
        elif k == "ports":
            dev.ports = {"v": v}
        elif k == "ip":
            dev.ip = {"v": v}
        else:
            setattr(dev, k, v)
    _sync_mac_identity(db, dev)
    _commit_or_409(db, f"Device with MAC {dev.mac} already exists")
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
        if k == "roles" and v is not None:
            dev.roles = {"v": v}
        elif k == "ports" and v is not None:
            dev.ports = {"v": v}
        elif k == "ip" and v is not None:
            dev.ip = {"v": v}
        else:
            setattr(dev, k, v)
    _sync_mac_identity(db, dev)
    _commit_or_409(db, f"Device with MAC {dev.mac} already exists")
    db.refresh(dev)
    return to_schema(dev)


@router.post(
    "/{device_id}/identities",
    response_model=schemas.DeviceIdentityRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=API_KEY_DEP,
)
def add_device_identity(device_id: str, payload: schemas.DeviceIdentityCreate, db: DbDep):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Not found")

    conflict = (
        db.query(models.DeviceIdentity)
        .filter(
            models.DeviceIdentity.source == payload.source,
            models.DeviceIdentity.external_id == payload.external_id,
        )
        .first()
    )
    if conflict and conflict.device_id != device_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Identity already bound to a different device",
        )
    if conflict:
        return schemas.DeviceIdentityRead.model_validate(conflict)

    identity = models.DeviceIdentity(
        id=schemas.new_id(),
        device_id=device_id,
        source=payload.source,
        external_id=payload.external_id,
    )
    db.add(identity)
    _commit_or_409(db, "Identity already bound to a different device")
    db.refresh(identity)
    return schemas.DeviceIdentityRead.model_validate(identity)


@router.get(
    "/{device_id}/identities",
    response_model=list[schemas.DeviceIdentityRead],
    dependencies=API_KEY_DEP,
)
def list_device_identities(device_id: str, db: DbDep):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Not found")
    rows = (
        db.query(models.DeviceIdentity)
        .filter(models.DeviceIdentity.device_id == device_id)
        .order_by(models.DeviceIdentity.created_at)
        .all()
    )
    return [schemas.DeviceIdentityRead.model_validate(r) for r in rows]


@router.post(
    "/{device_id}/observations",
    response_model=schemas.DeviceObservationRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=API_KEY_DEP,
)
def add_device_observation(device_id: str, payload: schemas.DeviceObservationCreate, db: DbDep):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Not found")

    obs = models.DeviceObservation(
        id=schemas.new_id(),
        device_id=device_id,
        source=payload.source,
        source_ref=payload.source_ref,
        observed_at=payload.observed_at or datetime.now(UTC),
        data=payload.data,
    )
    db.add(obs)
    db.commit()
    db.refresh(obs)
    return schemas.DeviceObservationRead.model_validate(obs)


@router.get(
    "/{device_id}/observations",
    response_model=list[schemas.DeviceObservationRead],
    dependencies=API_KEY_DEP,
)
def list_device_observations(device_id: str, db: DbDep):
    dev = db.get(models.Device, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Not found")
    rows = (
        db.query(models.DeviceObservation)
        .filter(models.DeviceObservation.device_id == device_id)
        .order_by(models.DeviceObservation.observed_at.desc())
        .all()
    )
    return [schemas.DeviceObservationRead.model_validate(r) for r in rows]


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
