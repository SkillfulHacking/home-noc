"""Persist TCP scan observations without changing device identity semantics."""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Device, DeviceObservation
from .schemas import new_id

MAX_TCP_OBSERVATIONS_PER_DEVICE = 100
SOURCE_REF_PREFIX = "tcp-connect:"


def _parse_observed_at(value: object) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _device_ips(device: Device) -> set[str]:
    values = (device.ip or {}).get("v", [])
    if not isinstance(values, list):
        return set()
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4:
            normalized.add(str(address))
    return normalized


def _canonical_open_port(device: Device, port: int) -> bool:
    """Add a new open port, preserving every existing operator-managed entry."""
    raw = (device.ports or {}).get("v", [])
    ports = list(raw) if isinstance(raw, list) else []
    for item in ports:
        if isinstance(item, dict) and item.get("proto") == "tcp" and item.get("port") == port:
            return False
    ports.append({"port": port, "proto": "tcp", "service": None, "state": "open"})
    device.ports = {"v": ports}
    return True


def _prune_history(db: Session, device_id: str) -> None:
    rows = list(
        db.scalars(
            select(DeviceObservation)
            .where(
                DeviceObservation.device_id == device_id,
                DeviceObservation.source == "scan",
                DeviceObservation.source_ref.like(f"{SOURCE_REF_PREFIX}%"),
            )
            .order_by(DeviceObservation.observed_at.desc(), DeviceObservation.id.desc())
        )
    )
    for stale in rows[MAX_TCP_OBSERVATIONS_PER_DEVICE:]:
        db.delete(stale)


def persist_tcp_scan_result(
    db: Session, job_id: str, result: dict
) -> None:
    """Associate observations by an unambiguous existing asset IPv4 address.

    IP addresses remain mutable attributes, not identities: this function
    never creates devices or identity rows. An absent or ambiguous match is
    reported in the job result and skipped safely.
    """
    if result.get("probe") != "tcp_connect":
        return

    by_host: dict[str, list[dict]] = defaultdict(list)
    for raw in result.get("observations", []):
        if not isinstance(raw, dict):
            continue
        try:
            host = str(ipaddress.IPv4Address(raw.get("host")))
            port = int(raw.get("port"))
        except (ipaddress.AddressValueError, TypeError, ValueError):
            continue
        if not 1 <= port <= 65_535 or raw.get("protocol") != "tcp":
            continue
        state = raw.get("state")
        if state not in {"open", "refused", "timeout", "inconclusive"}:
            continue
        by_host[host].append(
            {
                "port": port,
                "protocol": "tcp",
                "state": state,
                "observed_at": raw.get("observed_at"),
            }
        )

    matches: dict[str, list[Device]] = defaultdict(list)
    for device in db.scalars(select(Device)):
        for address in _device_ips(device):
            matches[address].append(device)

    observed_at = _parse_observed_at(result.get("finished_at"))
    matched_device_ids: set[str] = set()
    canonical_ports_added = 0
    unmatched_hosts = 0
    ambiguous_hosts = 0
    for host, observations in sorted(
        by_host.items(), key=lambda item: ipaddress.IPv4Address(item[0])
    ):
        devices = matches.get(host, [])
        if not devices:
            unmatched_hosts += 1
            continue
        if len(devices) != 1:
            ambiguous_hosts += 1
            continue
        device = devices[0]
        matched_device_ids.add(device.id)
        observations.sort(key=lambda item: item["port"])
        for observation in observations:
            if observation["state"] == "open" and _canonical_open_port(
                device, observation["port"]
            ):
                canonical_ports_added += 1

        # Multiple addresses belonging to the same asset must not overwrite
        # one another's observations from the same scan job.
        source_ref = f"{SOURCE_REF_PREFIX}{job_id}:{host}"
        existing = db.scalar(
            select(DeviceObservation).where(
                DeviceObservation.device_id == device.id,
                DeviceObservation.source == "scan",
                DeviceObservation.source_ref == source_ref,
            )
        )
        data = {"probe": "tcp_connect", "host": host, "ports": observations}
        if existing is None:
            db.add(
                DeviceObservation(
                    id=new_id(),
                    device_id=device.id,
                    source="scan",
                    source_ref=source_ref,
                    observed_at=observed_at,
                    data=data,
                )
            )
        else:
            existing.observed_at = observed_at
            existing.data = data
        db.flush()
        _prune_history(db, device.id)

    result["asset_persistence"] = {
        "matched_assets": len(matched_device_ids),
        "canonical_ports_added": canonical_ports_added,
        "unmatched_hosts": unmatched_hosts,
        "ambiguous_hosts": ambiguous_hosts,
    }
