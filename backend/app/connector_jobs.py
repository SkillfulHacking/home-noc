"""Worker executors for scheduled connector jobs (M16, issue #19).

``snmp_poll``: bounded identity + interface poll of devices that have both SNMPv3
credentials, each re-authorized against the live scan policy. ``unifi_sync``:
read-only controller import. Both persist through reconciliation (so ``last_seen``
only advances on a successful response) and return a summary; they never raise
raw exception text.
"""
from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import credentials as creds_svc
from . import crypto, scan_scope
from .connectors import snmp_service
from .connectors.base import ConnectorError
from .connectors.snmp import PySnmpTransport, SnmpTarget, SnmpTransport
from .connectors.unifi import HttpxUniFiHttp, UniFiConnector, UniFiHttp
from .connectors.unifi_sync import import_snapshot, record_outcome
from .models import ConnectorCredential, ConnectorSetting, Device
from .scan_runner import JobContext, RunnerError
from .scan_scope import ScanProfile, ScopeError

MAX_DEVICES_PER_JOB = 200
MAX_REPORTED = 50


def _first_ipv4(device: Device) -> str | None:
    for value in (device.ip or {}).get("v", []):
        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            continue
    return None


def _snmp_device_ids(db: Session, wanted: list[str]) -> list[str]:
    if wanted:
        return wanted[:MAX_DEVICES_PER_JOB]
    rows = db.execute(
        select(ConnectorCredential.device_id).where(
            ConnectorCredential.credential_type == "snmpv3_priv",
            ConnectorCredential.device_id.is_not(None))
    ).scalars()
    return list(rows)[:MAX_DEVICES_PER_JOB]


def run_snmp_poll(
    ctx: JobContext, session_factory: Callable[[], Session],
    transport: SnmpTransport | None = None,
) -> dict[str, Any]:
    transport = transport or PySnmpTransport()
    with session_factory() as db:
        device_ids = _snmp_device_ids(db, ctx.targets)
    summary = {"probe": "snmp_poll", "polled": 0, "failed": 0, "skipped": 0, "devices": []}
    ctx.progress(0, max(len(device_ids), 1))
    for index, device_id in enumerate(device_ids, start=1):
        ctx.check()
        outcome = "ok"
        with session_factory() as db:
            device = db.get(Device, device_id)
            address = _first_ipv4(device) if device else None
            try:
                if address is None:
                    raise ConnectorError("no_address", "Device has no IPv4 address")
                policy = ctx.policy_loader() if ctx.policy_loader else None
                try:
                    scan_scope.resolve_targets([address], ScanProfile.DISCOVERY, policy)
                except ScopeError:
                    summary["skipped"] += 1
                    outcome = "unauthorized"
                    raise ConnectorError("unauthorized", "Outside the authorized scan policy") \
                        from None
                usm = snmp_service.load_usm(db, device_id)
                facts, iface = asyncio.run(
                    snmp_service.collect(transport, SnmpTarget(address, usm)))
                snmp_service.persist(db, device, address, facts, iface)
                db.commit()
                summary["polled"] += 1
            except ConnectorError as exc:
                db.rollback()
                if outcome != "unauthorized":
                    summary["failed"] += 1
                    outcome = exc.code
        if len(summary["devices"]) < MAX_REPORTED:
            summary["devices"].append({"device_id": device_id, "outcome": outcome})
        ctx.progress(index, max(len(device_ids), 1))
    attempted = summary["polled"] + summary["failed"]
    if attempted and summary["polled"] == 0:
        raise RunnerError("poll_failed", "No SNMP device could be polled", retryable=False)
    return summary


def run_unifi_sync(
    ctx: JobContext, session_factory: Callable[[], Session],
    http_factory: Callable[[str, str, bool], UniFiHttp] | None = None,
) -> dict[str, Any]:
    http_factory = http_factory or (lambda base, tok, verify: HttpxUniFiHttp(base, tok, verify))
    with session_factory() as db:
        row = db.get(ConnectorSetting, "unifi")
        if row is None or not row.enabled or not row.base_url:
            raise RunnerError("connector_disabled", "The UniFi connector is disabled",
                              retryable=False)
        host = row.base_url.split("//", 1)[-1].split(":")[0]
        policy = ctx.policy_loader() if ctx.policy_loader else None
        try:
            scan_scope.resolve_targets([host], ScanProfile.DISCOVERY, policy)
        except ScopeError:
            raise RunnerError("unauthorized", "Controller is outside the authorized scan policy",
                              retryable=False) from None
        cred = creds_svc.find(db, creds_svc.Scope.connector("unifi"), "unifi_api_token")
        if cred is None:
            raise RunnerError("credentials_missing", "UniFi API token is not configured",
                              retryable=False)
        try:
            token = str(creds_svc.reveal(cred).get("token", ""))
        except crypto.CredentialCryptoError:
            raise RunnerError("credentials_unavailable", "Credential encryption is not available",
                              retryable=False) from None
        connector = UniFiConnector(http_factory(row.base_url, token, row.verify_tls))
        ctx.check()
        try:
            snapshot = asyncio.run(connector.collect_identity(row.site))
            counts = import_snapshot(db, snapshot)
        except ConnectorError as exc:
            db.rollback()
            row = db.get(ConnectorSetting, "unifi")
            record_outcome(row, ok=False, error_code=exc.code)
            db.commit()
            raise RunnerError(exc.code, exc.message, retryable=False) from None
        record_outcome(row, ok=True, summary=counts)
        db.commit()
    ctx.progress(1, 1)
    return {"probe": "unifi_sync", **counts}
