"""Device reachability, freshness and health snapshots (M19, issue #22).

Status is *derived* from per-source evidence, never from one blocked ping:

* every source (icmp, snmp, tcp, unifi) has its own freshness window;
* a failure only counts once ``CONFIRM_FAILURES`` consecutive attempts failed
  (an authoritative controller report such as UniFi "offline" confirms at once);
* only sources that have *ever succeeded* for the device can count against it,
  so an SNMP-only switch that never answers ICMP is not "offline" for that;
* ``last_seen`` (inventory freshness) is separate from health status.

Rules, in order (see ``evaluate``): never observed -> unknown; fresh source and
no confirmed-failing source -> online; fresh source but a confirmed-failing one ->
degraded; nothing fresh and a confirmed-failing source -> offline; nothing fresh
with unconfirmed failures -> degraded; nothing fresh and no failures -> unknown.
Callers own the transaction; nothing here commits.
"""
from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import events
from .models import Device, DeviceHealth, HealthSnapshot, ScanJob

SOURCES = ("icmp", "snmp", "tcp", "unifi")
FRESH_SECONDS = {"icmp": 900, "snmp": 900, "tcp": 3600, "unifi": 1800}
CONFIRM_FAILURES = 3
SNAPSHOT_HEARTBEAT = timedelta(hours=1)
MAX_SNAPSHOTS_PER_DEVICE = 500
ONLINE, DEGRADED, OFFLINE, UNKNOWN = "online", "degraded", "offline", "unknown"
STATUSES_ALL = (ONLINE, DEGRADED, OFFLINE, UNKNOWN)
# SNMP outcomes that mean "the device did not answer" (others prove it is alive).
SNMP_UNREACHABLE_CODES = {"timeout", "snmp_error"}
UNIFI_OFFLINE_STATES = {"OFFLINE", "DISCONNECTED"}


@dataclass(frozen=True)
class SourceState:
    last_success: datetime | None = None
    last_attempt: datetime | None = None
    failures: int = 0


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def load_sources(raw: dict | None) -> dict[str, SourceState]:
    out: dict[str, SourceState] = {}
    for name, item in (raw or {}).items():
        if name in SOURCES and isinstance(item, dict):
            failures = item.get("failures")
            out[name] = SourceState(
                _parse(item.get("last_success")), _parse(item.get("last_attempt")),
                failures if isinstance(failures, int) and failures >= 0 else 0)
    return out


def dump_sources(sources: dict[str, SourceState]) -> dict:
    return {n: {"last_success": _iso(s.last_success), "last_attempt": _iso(s.last_attempt),
                "failures": s.failures} for n, s in sources.items()}


def evaluate(sources: dict[str, SourceState], now: datetime) -> tuple[str, str]:
    """Pure state function: (status, reason)."""
    known = {n: s for n, s in sources.items() if s.last_success is not None}
    if not known:
        return UNKNOWN, "never observed successfully"
    confirmed = sorted(n for n, s in known.items() if s.failures >= CONFIRM_FAILURES)
    # A source confirmed failing since its last success is no longer "fresh": the
    # failures supersede the older success, whatever its age.
    fresh = sorted(n for n, s in known.items()
                   if n not in confirmed
                   and now - s.last_success <= timedelta(seconds=FRESH_SECONDS[n]))
    unconfirmed = sorted(n for n, s in known.items() if 0 < s.failures < CONFIRM_FAILURES)
    if fresh and not confirmed:
        return ONLINE, f"fresh {', '.join(fresh)} observation"
    if fresh:
        return DEGRADED, f"{', '.join(confirmed)} failing; {', '.join(fresh)} still responding"
    if confirmed:
        return OFFLINE, f"no fresh observation; {', '.join(confirmed)} failed repeatedly"
    if unconfirmed:
        names = ", ".join(unconfirmed)
        return DEGRADED, f"no fresh observation; {names} failures not yet confirmed"
    return UNKNOWN, "observations are stale; no failures recorded"


def _row(db: Session, device_id: str) -> DeviceHealth:
    row = db.get(DeviceHealth, device_id)
    if row is None:
        row = DeviceHealth(device_id=device_id, status=UNKNOWN, reason="never observed",
                           sources={})
        db.add(row)
        db.flush()
    return row


def _snapshot(db: Session, row: DeviceHealth, now: datetime, *, changed: bool) -> None:
    last = db.scalars(select(HealthSnapshot.at).where(HealthSnapshot.device_id == row.device_id)
                      .order_by(HealthSnapshot.at.desc()).limit(1)).first()
    if not changed and last is not None and now - last < SNAPSHOT_HEARTBEAT:
        return
    db.add(HealthSnapshot(id=str(uuid.uuid4()), device_id=row.device_id, at=now,
                          status=row.status, reason=row.reason))
    db.flush()
    keep = db.scalars(select(HealthSnapshot.id).where(HealthSnapshot.device_id == row.device_id)
                      .order_by(HealthSnapshot.at.desc(), HealthSnapshot.id.desc())
                      .offset(MAX_SNAPSHOTS_PER_DEVICE).limit(1000)).all()
    if keep:
        db.execute(delete(HealthSnapshot).where(HealthSnapshot.id.in_(keep)))


def _refresh(db: Session, row: DeviceHealth, now: datetime) -> bool:
    sources = load_sources(row.sources)
    status, reason = evaluate(sources, now)
    changed = status != row.status
    previous = row.status
    row.status, row.reason = status, reason
    if changed:
        events.on_health_transition(db, row.device_id, previous, status, reason, now)
    successes = [s.last_success for s in sources.values() if s.last_success]
    attempts = [s.last_attempt for s in sources.values() if s.last_attempt]
    row.last_success_at = max(successes) if successes else None
    row.last_attempt_at = max(attempts) if attempts else None
    if changed or row.status_changed_at is None:
        row.status_changed_at = now
    _snapshot(db, row, now, changed=changed)
    return changed


def record(db: Session, device_id: str, source: str, ok: bool, when: datetime | None = None,
           *, authoritative: bool = False) -> DeviceHealth:
    """Record one attempt. Out-of-order evidence (older than the stored attempt) is ignored."""
    if source not in SOURCES:
        raise ValueError(f"unknown health source {source!r}")
    now = when or datetime.now(UTC)
    row = _row(db, device_id)
    sources = load_sources(row.sources)
    cur = sources.get(source, SourceState())
    if cur.last_attempt is not None and now < cur.last_attempt:
        return row
    if ok:
        cur = SourceState(now, now, 0)
    else:
        failures = CONFIRM_FAILURES if authoritative else cur.failures + 1
        cur = SourceState(cur.last_success, now, failures)
    sources[source] = cur
    row.sources = dump_sources(sources)
    _refresh(db, row, max(now, row.last_attempt_at or now))
    return row


def sweep(db: Session, now: datetime | None = None, limit: int = 5000) -> int:
    """Re-derive status for time passing without new evidence. Returns changed count."""
    now = now or datetime.now(UTC)
    changed = 0
    for row in db.scalars(select(DeviceHealth).limit(limit)):
        if _refresh(db, row, now):
            changed += 1
    return changed


# ---- evidence adapters ------------------------------------------------------


def source_for_observation(source: str, data: dict) -> tuple[str, bool, bool] | None:
    """Map a reconciled observation to (health source, ok, authoritative) or None."""
    if source == "snmp":
        return "snmp", True, False
    if source == "scan" and data.get("probe") == "icmp_echo":
        return "icmp", True, False
    if source == "api" and data.get("connector") == "unifi":
        if data.get("kind") == "device":
            state = str(data.get("state") or "").upper()
            if state == "ONLINE":
                return "unifi", True, False
            if state in UNIFI_OFFLINE_STATES:
                return "unifi", False, True
            return None  # adopting/updating/unknown: not evidence either way
        return "unifi", True, False
    return None


def record_snmp_error(db: Session, device_id: str, code: str, when: datetime | None = None) -> None:
    if code in SNMP_UNREACHABLE_CODES:
        record(db, device_id, "snmp", False, when)


def record_icmp_misses(db: Session, job_id: str, responsive_ids: set[str],
                       answered_ips: set[str] | None = None, when: datetime | None = None) -> int:
    """Unanswered pings of known devices inside the job's targets are *weak* failures.

    A device is never charged if it was reconciled *or* any of its addresses answered
    (ambiguous/invalid hosts still answered, e.g. two devices sharing a reused IP)."""
    answered = answered_ips or set()
    job = db.get(ScanJob, job_id)
    if job is None:
        return 0
    nets = []
    for raw in (job.targets or {}).get("v", []):
        try:
            nets.append(ipaddress.IPv4Network(raw, strict=False))
        except ValueError:
            continue
    missed = 0
    for dev in db.scalars(select(Device)):
        if dev.id in responsive_ids:
            continue
        if any(v in answered for v in (dev.ip or {}).get("v", [])):
            continue
        for value in (dev.ip or {}).get("v", []):
            try:
                addr = ipaddress.IPv4Address(value)
            except ValueError:
                continue
            if any(addr in n for n in nets):
                record(db, dev.id, "icmp", False, when)
                missed += 1
                break
    return missed
