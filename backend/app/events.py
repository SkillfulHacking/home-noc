"""Operational events with deduplication (M20, issue #23).

One *actionable* event per real change; routine scans produce none:

* ``device_discovered`` - a new asset was created (once per device).
* ``address_changed`` / ``port_opened`` - a *new* IP or open port was added to an existing
  asset (deduped per value, so DHCP flapping between known addresses is silent).
* ``device_offline`` / ``device_degraded`` / ``device_recovered`` - health *transitions*
  (see ``app.health``); a cooldown folds flapping into one event with a count.
* ``managed_device_missing`` - a controller-managed device vanished from the controller.

``emit`` collapses a repeat of the same ``dedupe_key`` within ``cooldown`` into the
existing row (``count``, ``last_at``). Callers own the transaction; nothing commits here.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import Device, Event

SEVERITIES = ("info", "warning", "critical")
TYPES = ("device_discovered", "address_changed", "port_opened", "device_offline",
         "device_degraded", "device_recovered", "managed_device_missing", "finding_opened")
FLAP_COOLDOWN = timedelta(hours=1)
ONCE = timedelta(days=36500)  # effectively "only the first occurrence"
RETENTION = timedelta(days=90)
MAX_EVENTS = 20000


def emit(db: Session, type_: str, device_id: str | None, summary: str, *,
         severity: str = "info", details: dict | None = None, dedupe_key: str | None = None,
         cooldown: timedelta = FLAP_COOLDOWN, when: datetime | None = None) -> tuple[Event, bool]:
    """Record an event; returns (event, created). Repeats inside ``cooldown`` are counted."""
    if type_ not in TYPES or severity not in SEVERITIES:
        raise ValueError("unknown event type or severity")
    now = when or datetime.now(UTC)
    key = (dedupe_key or f"{type_}:{device_id or '-'}")[:160]
    recent = db.scalars(select(Event).where(Event.dedupe_key == key)
                        .order_by(Event.last_at.desc()).limit(1)).first()
    # A repeat folds into the existing row unless the operator already acknowledged it
    # (a new occurrence must be visible again); "once" events never recur at all.
    folds = recent is not None and (recent.acknowledged_at is None or cooldown >= ONCE)
    if folds and now - recent.last_at < cooldown:
        if now > recent.last_at:
            recent.last_at = now
        recent.count += 1
        db.flush()
        return recent, False
    hostname = None
    if device_id:
        device = db.get(Device, device_id)
        hostname = device.hostname if device else None
    event = Event(id=str(uuid.uuid4()), at=now, last_at=now, type=type_, severity=severity,
                  device_id=device_id, hostname=hostname, summary=summary[:255],
                  details=details or {}, dedupe_key=key, count=1)
    db.add(event)
    db.flush()
    return event, True


# ---- adapters called from reconcile / health / ports / connectors ----------------


def on_device_created(db: Session, device_id: str, source: str, hostname: str,
                      when: datetime | None = None) -> None:
    emit(db, "device_discovered", device_id, f"New device discovered: {hostname}",
         details={"source": source}, dedupe_key=f"device_discovered:{device_id}",
         cooldown=ONCE, when=when)


def on_addresses_added(db: Session, device_id: str, added: list[str],
                       when: datetime | None = None) -> None:
    for ip in added:
        emit(db, "address_changed", device_id, f"New address {ip}", details={"ip": ip},
             dedupe_key=f"address_changed:{device_id}:{ip}", cooldown=ONCE, when=when)


def on_ports_opened(db: Session, device_id: str, ports: list[tuple[str, int]],
                    when: datetime | None = None) -> None:
    for proto, port in ports:
        emit(db, "port_opened", device_id, f"New open {proto.upper()} port {port}",
             severity="warning", details={"port": port, "proto": proto},
             dedupe_key=f"port_opened:{device_id}:{proto}:{port}", cooldown=ONCE, when=when)


def on_health_transition(db: Session, device_id: str, old: str, new: str, reason: str,
                         when: datetime | None = None) -> None:
    """Only meaningful transitions; online->unknown (data simply aged) is silent."""
    details = {"from": old, "to": new, "reason": reason}
    if new == "offline":
        emit(db, "device_offline", device_id, "Device is offline", severity="critical",
             details=details, when=when)
    elif new == "degraded":
        emit(db, "device_degraded", device_id, "Device is degraded", severity="warning",
             details=details, when=when)
    elif new == "online" and old in ("offline", "degraded"):
        emit(db, "device_recovered", device_id, "Device recovered", details=details, when=when)


def on_finding_opened(db: Session, device_id: str, finding_id: str, name: str, severity: str,
                      when: datetime | None = None) -> None:
    emit(db, "finding_opened", device_id, f"New {severity} finding: {name}",
         severity="critical" if severity in ("high", "critical") else "warning",
         details={"finding_id": finding_id, "finding_severity": severity},
         dedupe_key=f"finding_opened:{finding_id}", cooldown=ONCE, when=when)


def on_managed_missing(db: Session, device_id: str, source: str,
                       when: datetime | None = None) -> None:
    emit(db, "managed_device_missing", device_id, f"Managed device missing from {source}",
         severity="warning", details={"source": source},
         dedupe_key=f"managed_device_missing:{source}:{device_id}",
         cooldown=timedelta(days=7), when=when)


def prune(db: Session, now: datetime | None = None) -> int:
    """Retention: drop events older than RETENTION and anything beyond MAX_EVENTS."""
    now = now or datetime.now(UTC)
    removed = db.execute(delete(Event).where(Event.last_at < now - RETENTION)).rowcount or 0
    extra = db.scalars(select(Event.id).order_by(Event.at.desc(), Event.id.desc())
                       .offset(MAX_EVENTS).limit(5000)).all()
    if extra:
        removed += db.execute(delete(Event).where(Event.id.in_(extra))).rowcount or 0
    return removed
