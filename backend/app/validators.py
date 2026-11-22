# backend/app/validators.py
from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2})([:-]?)(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}$")
_MISSING_SNMP_PREFIXES = ("no such object", "no such instance", "end of mib")


def normalize_ip(value: str) -> str:
    """Validate and normalize an IPv4/IPv6 address to its canonical string form."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc


def normalize_mac(value: str) -> str:
    """Validate a MAC address (colon/dash/bare hex) and normalize to lowercase colon form."""
    v = value.strip()
    if not _MAC_RE.match(v):
        raise ValueError(f"Invalid MAC address: {value!r}")
    hex_digits = re.sub(r"[:-]", "", v).lower()
    return ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2))


def ensure_utc(value: datetime) -> datetime:
    """Normalize a datetime to timezone-aware UTC.

    Naive datetimes are assumed to already be UTC (matching storage behavior),
    rather than rejected, so existing callers that send naive timestamps keep working.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def normalize_hardware_text(value: str | None) -> str | None:
    """Trim discovered hardware text and discard standard SNMP absence sentinels."""
    if value is None:
        return None
    cleaned = value.strip()
    if cleaned.lower().startswith(_MISSING_SNMP_PREFIXES):
        return None
    return cleaned or None
