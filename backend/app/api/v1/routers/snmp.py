"""SNMP connect-test route (M13, issue #16).

Admin session + CSRF required (``require_session``). The target must be one of
the device's own IPv4 addresses *and* inside the current scan policy; stored
SNMPv3 credentials are decrypted in-process only and never returned or logged.
Responses are ``Cache-Control: no-store``.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from .... import credentials as creds_svc
from .... import crypto, key_binding, models
from ....connectors.base import ConnectorError
from ....connectors.snmp import (
    PySnmpTransport,
    SnmpConnector,
    SnmpTarget,
    SnmpTransport,
    UsmCredentials,
)
from ....connectors.snmp_interfaces import collect_interfaces
from ....connectors.snmp_sync import persist_poll
from ....dependencies import get_db
from ....scan_scope import ScanProfile, ScopeError, log_authorization, resolve_targets
from ....security import require_session

logger = logging.getLogger(__name__)
_slots = threading.BoundedSemaphore(2)  # at most two concurrent SNMP tests


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def get_snmp_transport() -> SnmpTransport:
    return PySnmpTransport()


router = APIRouter(
    prefix="/devices/{device_id}/snmp",
    tags=["snmp"],
    dependencies=[Depends(_no_store)],
)


class SnmpTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str | None = None


class SnmpTestResponse(BaseModel):
    ok: bool
    result: dict | None = None
    error: dict | None = None


def _device_ipv4s(device: models.Device) -> list[str]:
    out: list[str] = []
    for value in (device.ip or {}).get("v", []):
        try:
            out.append(str(ipaddress.IPv4Address(value)))
        except ValueError:
            continue
    return out


def _load_usm(db: Session, device_id: str) -> UsmCredentials:
    scope = creds_svc.Scope.device(device_id)
    auth = creds_svc.find(db, scope, "snmpv3_auth")
    priv = creds_svc.find(db, scope, "snmpv3_priv")
    if auth is None or priv is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="SNMPv3 authentication and privacy credentials must both be configured",
        )
    try:
        auth_secret = creds_svc.reveal(auth)
        priv_secret = creds_svc.reveal(priv)
        from pydantic import SecretStr

        return UsmCredentials(
            username=str((auth.meta or {}).get("username", "")),
            auth_protocol=str((auth.meta or {}).get("protocol", "SHA256")),
            auth_key=SecretStr(str(auth_secret.get("password", ""))),
            priv_protocol=str((priv.meta or {}).get("protocol", "AES128")),
            priv_key=SecretStr(str(priv_secret.get("password", ""))),
        )
    except crypto.CredentialCryptoError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Credential encryption is not available"
        ) from None


def _prepare(db: Session, device_id: str, body: SnmpTestRequest, session, outcome: str):
    """Validate key, device, address, scope policy and credentials (no network I/O)."""
    try:
        key_binding.check_usable(db)
    except crypto.CredentialCryptoError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Credential encryption is not available"
        ) from None
    device = db.get(models.Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    addresses = _device_ipv4s(device)
    if body.ip is not None:
        try:
            wanted = str(ipaddress.IPv4Address(body.ip))
        except ValueError:
            raise HTTPException(422, detail="ip must be an IPv4 address") from None
        if wanted not in addresses:
            raise HTTPException(422, detail="ip is not an address of this device")
        address = wanted
    elif addresses:
        address = addresses[0]
    else:
        raise HTTPException(422, detail="Device has no IPv4 address")

    try:
        networks, count = resolve_targets([address], ScanProfile.DISCOVERY)
    except ScopeError as exc:
        log_authorization(operator=session.username, profile=ScanProfile.DISCOVERY, networks=[],
                          count=0, dry_run=False, outcome=f"snmp_rejected:{exc.code}")
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Target is outside the authorized "
                            "scan policy") from None
    usm = _load_usm(db, device_id)
    log_authorization(operator=session.username, profile=ScanProfile.DISCOVERY,
                      networks=networks, count=count, dry_run=False, outcome=outcome)
    return device, address, usm


@router.post("/test", response_model=SnmpTestResponse)
def test_snmp(
    device_id: Annotated[str, Path(min_length=1, max_length=36)],
    body: SnmpTestRequest,
    session=Depends(require_session),
    db: Session = Depends(get_db),
    transport: SnmpTransport = Depends(get_snmp_transport),
) -> SnmpTestResponse:
    _device, address, usm = _prepare(db, device_id, body, session, "snmp_test")
    if not _slots.acquire(blocking=False):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many SNMP tests running")
    try:
        connector = SnmpConnector(transport)
        try:
            result = asyncio.run(connector.test_connection(SnmpTarget(address, usm)))
        except ConnectorError as exc:
            return SnmpTestResponse(ok=False, error={"code": exc.code, "message": exc.message})
        return SnmpTestResponse(ok=True, result=result)
    finally:
        _slots.release()


@router.post("/poll")
def poll_snmp(
    device_id: Annotated[str, Path(min_length=1, max_length=36)],
    body: SnmpTestRequest,
    session=Depends(require_session),
    db: Session = Depends(get_db),
    transport: SnmpTransport = Depends(get_snmp_transport),
) -> dict:
    """Identity + bounded interface poll, persisted through reconciliation."""
    device, address, usm = _prepare(db, device_id, body, session, "snmp_poll")
    if not _slots.acquire(blocking=False):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many SNMP tests running")
    try:
        connector = SnmpConnector(transport)
        target = SnmpTarget(address, usm)

        async def go():
            facts = await connector.collect_identity(target)
            return facts, await collect_interfaces(transport, target, facts)

        try:
            facts, iface = asyncio.run(go())
            summary = persist_poll(db, device, address, facts, iface)
            db.commit()
        except ConnectorError as exc:
            db.rollback()
            return {"ok": False, "error": {"code": exc.code, "message": exc.message}}
        return {"ok": True, "result": summary}
    finally:
        _slots.release()
