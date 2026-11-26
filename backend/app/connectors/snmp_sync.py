"""Persist an SNMP poll for one existing device through reconciliation (M15).

The observation is attached to the polled device by its own IP. If reconciliation
would route it elsewhere (ambiguous or conflicting evidence) nothing is written.
Derived roles are applied only when the device has none (curated roles win).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from ..models import Device
from ..reconcile import AmbiguousObservation, ReconcileObservation, reconcile_observation
from .base import ConnectorError


def persist_poll(
    db: Session, device: Device, address: str, facts: dict[str, Any], iface: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    data = {
        "connector": "snmp",
        "identity": {k: facts.get(k) for k in
                     ("sys_name", "sys_descr", "sys_object_id", "sys_uptime", "engine_id",
                      "identity_key")},
        "interfaces": iface["interfaces"],
        "interfaces_ignored": iface["ignored"],
        "interfaces_truncated": iface["truncated"],
        "derived_roles": iface["roles"],
    }
    obs = ReconcileObservation(source="snmp", source_ref=f"snmp:{address}", observed_at=now,
                               ip=[address], data=data)
    try:
        result = reconcile_observation(db, obs)
    except AmbiguousObservation:
        raise ConnectorError("ambiguous_device", "Address matches several devices") from None
    if result.device_id != device.id:
        db.rollback()
        raise ConnectorError("device_mismatch", "Observation did not match the polled device")
    roles_applied = False
    current = (device.roles or {}).get("v", [])
    if iface["roles"] and not current:
        device.roles = {"v": list(iface["roles"])}
        roles_applied = True
    return {"interfaces": len(iface["interfaces"]), "ignored": iface["ignored"],
            "truncated": iface["truncated"], "roles": iface["roles"],
            "roles_applied": roles_applied}
