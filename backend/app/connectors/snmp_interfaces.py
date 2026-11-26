"""Bounded interface inventory and role derivation over SNMP (M15, issue #18).

* Walks only the allowlisted IF-MIB columns below, with a hard row cap and an
  overall time budget per device; partial tables are reported as truncated.
* Rows with a weird/empty index, non-physical type or unusable identifiers are
  ignored and counted, never guessed.
* Interface MACs are stored only inside the interface list; they never become
  the device MAC (virtual/bridge/bond interfaces reuse or share addresses).
* Roles come from standard MIB-II/Bridge-MIB semantics (sysServices layer bits,
  ipForwarding, dot1dBaseBridgeAddress) -- never from vendor description strings.
"""
from __future__ import annotations

import re
import time
from typing import Any

from ..validators import normalize_mac
from .base import ConnectorError
from .snmp import SnmpTarget, SnmpTransport, _clean_text, _Missing, validate_credentials

MAX_INTERFACES = 512
WALK_BUDGET_SECONDS = 20.0

IF_COLUMNS: dict[str, str] = {
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "type": "1.3.6.1.2.1.2.2.1.3",
    "phys_address": "1.3.6.1.2.1.2.2.1.6",
    "oper_status": "1.3.6.1.2.1.2.2.1.8",
    "name": "1.3.6.1.2.1.31.1.1.1.1",
}
ALLOWED_TABLE_PREFIXES = frozenset(IF_COLUMNS.values())

# ifType values that are physical ports (ethernet family, Wi-Fi).
PHYSICAL_IF_TYPES = frozenset({6, 62, 69, 71, 117})
OPER_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant",
               6: "notPresent", 7: "lowerLayerDown"}
_SUFFIX = re.compile(r"^(\d+)$")


def _index(oid: str, prefix: str) -> int | None:
    if not oid.startswith(prefix + "."):
        return None
    match = _SUFFIX.match(oid[len(prefix) + 1:])
    if not match:
        return None
    value = int(match.group(1))
    return value if 0 < value < 2**31 else None


def _mac(raw: Any) -> str | None:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 6 or not any(raw):
        return None
    try:
        return normalize_mac(":".join(f"{b:02x}" for b in raw))
    except ValueError:
        return None


def normalize_interfaces(columns: dict[str, dict[int, Any]]) -> tuple[list[dict], int]:
    """Build interface dicts from per-column {ifIndex: raw}; returns (rows, ignored)."""
    indexes = set().union(*(set(c) for c in columns.values())) if columns else set()
    rows, ignored = [], 0
    for idx in sorted(indexes):
        raw_type = columns.get("type", {}).get(idx)
        if not isinstance(raw_type, int) or isinstance(raw_type, bool) \
                or raw_type not in PHYSICAL_IF_TYPES:
            ignored += 1
            continue
        name = _clean_text(columns.get("name", {}).get(idx), 64)
        descr = _clean_text(columns.get("descr", {}).get(idx), 255)
        if not (name or descr):
            ignored += 1
            continue
        status = columns.get("oper_status", {}).get(idx)
        rows.append({
            "if_index": idx,
            "name": name or descr,
            "descr": descr,
            "if_type": raw_type,
            "mac": _mac(columns.get("phys_address", {}).get(idx)),
            "oper_status": OPER_STATUS.get(status) if isinstance(status, int) else None,
        })
    return rows, ignored


def derive_roles(facts: dict[str, Any], interface_count: int) -> list[str]:
    """Roles from standard MIB semantics only; empty when evidence is insufficient."""
    roles: list[str] = []
    services = facts.get("sys_services")
    layer2 = isinstance(services, int) and bool(services & 0b10)
    layer3 = isinstance(services, int) and bool(services & 0b100)
    if layer2 and facts.get("bridge_address") and interface_count >= 2:
        roles.append("switch")
    if layer3 and facts.get("ip_forwarding") == 1 and interface_count >= 2:
        roles.append("router")
    return roles


async def collect_interfaces(
    transport: SnmpTransport, target: SnmpTarget, facts: dict[str, Any]
) -> dict[str, Any]:
    """Walk the allowlisted columns within the per-device time and row budget."""
    validate_credentials(target.credentials)
    started = time.monotonic()
    columns: dict[str, dict[int, Any]] = {}
    truncated = False
    for key, prefix in IF_COLUMNS.items():
        assert prefix in ALLOWED_TABLE_PREFIXES  # noqa: S101 - allowlist invariant
        remaining = WALK_BUDGET_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            truncated = True
            break
        try:
            rows = await transport.walk(target, prefix, max_rows=MAX_INTERFACES + 1,
                                        deadline=remaining)
        except ConnectorError:
            raise
        if len(rows) > MAX_INTERFACES:
            truncated = True
            rows = rows[:MAX_INTERFACES]
        column: dict[int, Any] = {}
        for oid, value in rows:
            idx = _index(oid, prefix)
            if idx is None or isinstance(value, _Missing):
                continue
            column[idx] = value
        columns[key] = column
    interfaces, ignored = normalize_interfaces(columns)
    return {"interfaces": interfaces, "ignored": ignored, "truncated": truncated,
            "roles": derive_roles(facts, len(interfaces))}
