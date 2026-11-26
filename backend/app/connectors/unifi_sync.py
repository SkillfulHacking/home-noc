"""Import a UniFi snapshot into the inventory through reconciliation (M14).

UniFi device ids are trusted vendor identifiers (``unifi``); clients are bound
by MAC with a separate ``unifi_client`` identifier. Curated asset fields are
never overwritten (see ``app.reconcile``); IPs/ports/last_seen only move
forward. Callers own the transaction.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import events
from ..models import ConnectorSetting, DeviceObservation
from ..reconcile import AmbiguousObservation, ReconcileObservation, reconcile_observation

VENDOR = "Ubiquiti"


def _known_in_site(db: Session, site: str) -> dict[str, str]:
    """UniFi device ids previously seen *in this site* (a site change must not look like
    every device disappearing)."""
    known: dict[str, str] = {}
    prefix = "unifi:device:"
    rows = db.scalars(select(DeviceObservation).where(
        DeviceObservation.source == "api", DeviceObservation.source_ref.like(f"{prefix}%")))
    for row in rows:
        if ((row.data or {}).get("extra") or {}).get("site") == site:
            known[row.source_ref[len(prefix):]] = row.device_id
    return known


def import_snapshot(db: Session, snapshot: dict[str, Any], now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    known_before = _known_in_site(db, snapshot["site"])
    counts = {"devices_created": 0, "devices_merged": 0, "clients_created": 0,
              "clients_merged": 0, "ambiguous": 0, "invalid": snapshot.get("skipped", 0)}
    for kind, rows in (("device", snapshot["devices"]), ("client", snapshot["clients"])):
        for row in rows:
            try:
                obs = ReconcileObservation(
                    source="api",
                    source_ref=f"unifi:{kind}:{row['id']}",
                    observed_at=now,
                    hostname=row.get("name") if kind == "device" else None,
                    ip=[row["ip"]] if row.get("ip") else [],
                    mac=row.get("mac"),
                    identifiers={"unifi" if kind == "device" else "unifi_client": row["id"]},
                    vendor=VENDOR if kind == "device" else None,
                    model=row.get("model") if kind == "device" else None,
                    data={"connector": "unifi", "kind": kind, "site": snapshot["site"],
                          **{k: v for k, v in row.items() if k not in {"id", "mac", "ip"}}},
                )
                result = reconcile_observation(db, obs)
            except ValidationError:
                counts["invalid"] += 1
                continue
            except AmbiguousObservation:
                counts["ambiguous"] += 1
                continue
            counts[f"{kind}s_{result.action}"] += 1
    present = {row["id"] for row in snapshot["devices"]}
    counts["devices_missing"] = 0
    if snapshot.get("skipped_devices", 0) == 0:  # an incomplete list cannot prove absence
        for external_id, device_id in known_before.items():
            if external_id not in present:  # a managed device vanished from the controller
                events.on_managed_missing(db, device_id, "unifi", now)
                counts["devices_missing"] += 1
    return counts


def record_outcome(
    row: ConnectorSetting, *, ok: bool, error_code: str | None = None,
    summary: dict | None = None, now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    row.last_attempt_at = now
    if ok:
        row.last_status, row.last_error_code = "ok", None
        row.last_success_at, row.consecutive_failures = now, 0
        row.last_summary = summary
    else:
        row.last_status, row.last_error_code = "error", (error_code or "error")[:64]
        row.consecutive_failures = (row.consecutive_failures or 0) + 1
