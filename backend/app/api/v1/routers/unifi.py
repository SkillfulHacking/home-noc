"""UniFi connector settings, connect-test and manual sync (M14, issue #17).

A disabled connector is never contacted by sync (and, in later milestones, by
scheduled polling). ``/test`` is an explicit admin action and may run before enabling.

Admin session + CSRF on every route. The controller must be an ``https://``
IPv4 literal that passes the runtime scan policy (checked when saved *and* on
each use). The API token is decrypted in-process only and never returned.
Everything is GET against the controller; nothing mutates it.
"""
from __future__ import annotations

import asyncio
import ipaddress
import threading
from collections.abc import Callable
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .... import credentials as creds_svc
from .... import crypto, key_binding
from ....connectors.base import ConnectorError
from ....connectors.unifi import HttpxUniFiHttp, UniFiConnector, UniFiHttp
from ....connectors.unifi_sync import import_snapshot, record_outcome
from ....dependencies import get_db
from ....models import ConnectorSetting
from ....scan_scope import ScanProfile, ScopeError, log_authorization, resolve_targets
from ....security import require_session

NAME = "unifi"
_sync_slot = threading.BoundedSemaphore(1)
HttpFactory = Callable[[str, str, bool], UniFiHttp]


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def get_http_factory() -> HttpFactory:
    return lambda base, token, verify: HttpxUniFiHttp(base, token, verify)


router = APIRouter(prefix="/connectors/unifi", tags=["unifi"], dependencies=[Depends(_no_store)])
DbDep = Annotated[Session, Depends(get_db)]


class UniFiSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    base_url: str | None = Field(default=None, max_length=255)
    site: str | None = Field(default=None, max_length=64, pattern=r"^[\w .:-]*$")
    verify_tls: bool = True


def normalize_base_url(raw: str) -> tuple[str, str]:
    """Return (normalized https://ip[:port], host) or raise ValueError."""
    parts = urlsplit(raw.strip())
    if parts.scheme != "https" or parts.username or parts.password or parts.query \
            or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("base_url must look like https://<ipv4>[:port]")
    try:
        host = str(ipaddress.IPv4Address(parts.hostname or ""))
        port = parts.port
    except ValueError:
        raise ValueError("base_url must use an IPv4 address and a valid port") from None
    return (f"https://{host}:{port}" if port else f"https://{host}"), host


def _view(row: ConnectorSetting, configured: bool) -> dict:
    return {
        "name": NAME, "enabled": row.enabled, "base_url": row.base_url, "site": row.site,
        "verify_tls": row.verify_tls, "credential_configured": configured,
        "last_status": row.last_status, "last_error_code": row.last_error_code,
        "last_attempt_at": row.last_attempt_at, "last_success_at": row.last_success_at,
        "consecutive_failures": row.consecutive_failures or 0, "last_summary": row.last_summary,
    }


def _row(db: Session) -> ConnectorSetting:
    """Existing row or a *transient* default. Never writes: scope-policy loading may
    seed its own row on another connection, which a pending write here would lock."""
    return db.get(ConnectorSetting, NAME) or ConnectorSetting(
        name=NAME, enabled=False, verify_tls=True, consecutive_failures=0)


def _credential_row(db: Session):
    return creds_svc.find(db, creds_svc.Scope.connector(NAME), "unifi_api_token")


def _guard_key(db: Session) -> None:
    try:
        key_binding.check_usable(db)
    except crypto.CredentialCryptoError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Credential encryption is not available"
        ) from None


def _authorize(row: ConnectorSetting, session, outcome: str) -> None:
    if not row.base_url:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Controller URL is not configured")
    host = urlsplit(row.base_url).hostname or ""
    try:
        networks, count = resolve_targets([host], ScanProfile.DISCOVERY)
    except ScopeError as exc:
        log_authorization(operator=session.username, profile=ScanProfile.DISCOVERY, networks=[],
                          count=0, dry_run=False, outcome=f"unifi_rejected:{exc.code}")
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="Controller is outside the authorized scan policy"
        ) from None
    log_authorization(operator=session.username, profile=ScanProfile.DISCOVERY,
                      networks=networks, count=count, dry_run=False, outcome=outcome)


def _client(db: Session, row: ConnectorSetting, factory: HttpFactory) -> UniFiConnector:
    cred = _credential_row(db)
    if cred is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="UniFi API token is not configured")
    try:
        token = str(creds_svc.reveal(cred).get("token", ""))
    except crypto.CredentialCryptoError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Credential encryption is not available"
        ) from None
    return UniFiConnector(factory(row.base_url or "", token, row.verify_tls))


@router.get("")
def read_settings(db: DbDep, _s=Depends(require_session)) -> dict:
    row = _row(db)
    return _view(row, _credential_row(db) is not None)


@router.put("")
def save_settings(body: UniFiSettingsIn, db: DbDep, session=Depends(require_session)) -> dict:
    row = _row(db)
    new_url: str | None = None
    if body.base_url:
        try:
            new_url, _host = normalize_base_url(body.base_url)
        except ValueError as exc:
            raise HTTPException(422, detail=str(exc)) from None
        # Authorize before touching the session so no write transaction is pending
        # while the scan policy is loaded.
        _authorize(ConnectorSetting(name=NAME, base_url=new_url), session, "unifi_settings")
    elif body.enabled:
        raise HTTPException(422, detail="base_url is required to enable the connector")
    row.base_url = new_url
    db.add(row)
    row.enabled = body.enabled
    row.site = body.site or None
    row.verify_tls = body.verify_tls
    db.commit()
    return _view(row, _credential_row(db) is not None)


@router.post("/test")
def test_connection(
    db: DbDep, session=Depends(require_session),
    factory: HttpFactory = Depends(get_http_factory),
) -> dict:
    _guard_key(db)
    row = _row(db)
    _authorize(row, session, "unifi_test")
    connector = _client(db, row, factory)
    try:
        return {"ok": True, "result": asyncio.run(connector.test_connection())}
    except ConnectorError as exc:
        return {"ok": False, "error": {"code": exc.code, "message": exc.message}}


@router.post("/sync")
def sync(
    db: DbDep, session=Depends(require_session),
    factory: HttpFactory = Depends(get_http_factory),
) -> dict:
    _guard_key(db)
    row = _row(db)
    if not row.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="The UniFi connector is disabled")
    _authorize(row, session, "unifi_sync")
    connector = _client(db, row, factory)
    if not _sync_slot.acquire(blocking=False):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="A sync is already running")
    try:
        try:
            snapshot = asyncio.run(connector.collect_identity(row.site))
            counts = import_snapshot(db, snapshot)
        except ConnectorError as exc:
            db.rollback()
            row = _row(db)
            db.add(row)
            record_outcome(row, ok=False, error_code=exc.code)
            db.commit()
            return {"ok": False, "error": {"code": exc.code, "message": exc.message}}
        db.add(row)
        record_outcome(row, ok=True, summary=counts)
        db.commit()
        return {"ok": True, "result": counts}
    finally:
        _sync_slot.release()
