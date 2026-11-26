"""Reconcile source observations into the deduplicated device inventory (M12).

Identity priority, strongest first:

1. trusted vendor/connector identifiers (``DeviceIdentity`` rows, e.g. a UniFi
   device id),
2. normalized MAC address,
3. IP address / hostname -- *weak*, mutable attributes used with caution: an IP
   match is only accepted when it is unique and nothing contradicts it (a
   different MAC, a different vendor id, a different real hostname).

Serial numbers are deliberately not identities: generic/duplicated serials
would collapse unrelated hosts. They only fill an empty field.

Safety rules:

* Curated asset fields (``hostname``, ``location``, ``roles``, ``notes``,
  ``snmp``, ``api``) are never overwritten. ``hostname`` is replaced only when
  it is an auto-generated placeholder (equal to one of the device's IPs).
  ``vendor``/``model``/``os``/``serial``/``mac`` are filled only when empty; a
  disagreeing report is kept as a *conflict* on the observation instead.
* ``first_seen`` only moves earlier, ``last_seen`` only moves later, IPs and
  ports are unioned (never removed), so churn cannot erase history.
* A stale observation (older than the stored one for the same source and
  ``source_ref``) neither replaces that row nor changes device attributes.
* Contradicting strong identities never merge two devices; the conflict is
  recorded in the observation's ``reconciliation`` block; disputed facts
  are quarantined instead of applied to canonical inventory.
* Observations are one row per (device, source, source_ref) and are updated in
  place, so repeated scans do not grow history without bound.

Nothing here commits; callers own the transaction. Ambiguity is detected before
any write so a rejected observation leaves the session untouched.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import events, health
from .models import Device, DeviceIdentity, DeviceObservation
from .port_observations import persist_tcp_scan_result
from .schemas import (
    DiscoveryMethod,
    Port,
    _find_forbidden_key,
    new_id,
)
from .validators import ensure_utc, normalize_hardware_text, normalize_ip, normalize_mac

MAX_IPS_PER_DEVICE = 32
MAX_PORTS_PER_DEVICE = 1024
FUTURE_SKEW = timedelta(minutes=5)
# ``mac`` has its own field; ip/hostname are mutable and never identities.
_RESERVED_IDENTIFIER_SOURCES = {"ip", "ipv4", "ipv6", "hostname", "mac"}
_HARDWARE_FIELDS = ("vendor", "model", "os", "serial")


class AmbiguousObservation(Exception):
    """Weak evidence matches several devices; nothing was written."""


class ReconcileObservation(BaseModel):
    """A non-secret sighting from one source, as input to reconciliation."""

    model_config = ConfigDict(extra="forbid")

    source: DiscoveryMethod
    source_ref: str | None = Field(default=None, max_length=255)
    observed_at: datetime | None = None
    hostname: str | None = Field(default=None, max_length=255)
    ip: list[str] = Field(default_factory=list, max_length=MAX_IPS_PER_DEVICE)
    mac: str | None = None
    identifiers: dict[str, str] = Field(default_factory=dict)
    vendor: str | None = Field(default=None, max_length=255)
    model: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=255)
    serial: str | None = Field(default=None, max_length=255)
    ports: list[Port] = Field(default_factory=list, max_length=256)
    data: dict = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def _tz(cls, v: datetime | None) -> datetime | None:
        return ensure_utc(v) if v is not None else v

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str | None) -> str | None:
        v = v.strip() if v else v
        return v or None

    @field_validator("ip")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            normalized = normalize_ip(raw)
            addr = ipaddress.ip_address(normalized)
            if addr.is_unspecified or addr.is_loopback or addr.is_multicast:
                raise ValueError(f"IP address {normalized} cannot identify a device")
            if normalized not in out:
                out.append(normalized)
        return out

    @field_validator("mac")
    @classmethod
    def _mac(cls, v: str | None) -> str | None:
        return normalize_mac(v) if v else None

    @field_validator("identifiers")
    @classmethod
    def _identifiers(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 8:
            raise ValueError("at most 8 identifiers per observation")
        out: dict[str, str] = {}
        for key, value in v.items():
            source = str(key).strip().lower()
            ext = str(value).strip()
            if not source or len(source) > 64 or not ext or len(ext) > 255:
                raise ValueError("identifier source/value must be 1-64 / 1-255 characters")
            if source in _RESERVED_IDENTIFIER_SOURCES:
                raise ValueError(f"{source!r} is not a trusted vendor identifier source")
            # Identifier names must never become a back door for credential
            # values in device_identities or readable observation provenance.
            if _find_forbidden_key({source: ext}) is not None:
                raise ValueError("credential-shaped identifier source is forbidden")
            if source in out:
                raise ValueError("duplicate identifier source after normalization")
            out[source] = ext
        return out

    @field_validator("vendor", "model", "os", "serial", mode="before")
    @classmethod
    def _hardware(cls, v: object) -> object:
        return normalize_hardware_text(v) if isinstance(v, str) else v

    @field_validator("data")
    @classmethod
    def _no_secrets(cls, v: dict) -> dict:
        bad = _find_forbidden_key(v)
        if bad is not None:
            raise ValueError(f"observation data must not include credential field {bad!r}")
        return v

    @model_validator(mode="after")
    def _needs_evidence(self) -> ReconcileObservation:
        if not (self.ip or self.mac or self.identifiers or self.hostname):
            raise ValueError("observation needs at least one of ip, mac, identifiers, hostname")
        return self


@dataclass
class ReconcileResult:
    device_id: str
    observation_id: str | None
    action: str  # "created" | "merged"
    matched_by: str  # "identifier" | "mac" | "ip" | "hostname" | "new"
    stale: bool = False
    applied_fields: list[str] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)


# -- helpers ---------------------------------------------------------------


def _device_ips(dev: Device) -> list[str]:
    raw = (dev.ip or {}).get("v", [])
    return [x for x in raw if isinstance(x, str)] if isinstance(raw, list) else []


def _is_placeholder_hostname(dev: Device, db: Session | None = None) -> bool:
    """Empty, or an auto-generated name (an IP, the MAC, or a bound vendor id)."""
    name = (dev.hostname or "").strip().lower()
    if not name:
        return True
    auto = {ip.lower() for ip in _device_ips(dev)}
    if dev.mac:
        auto.add(dev.mac.strip().lower())
    if db is not None:
        auto |= {v.strip().lower() for v in _identities(db, dev.id).values()}
    return name in auto


def _identity_owner(db: Session, source: str, external_id: str) -> str | None:
    return db.scalar(
        select(DeviceIdentity.device_id).where(
            DeviceIdentity.source == source, DeviceIdentity.external_id == external_id
        )
    )


def _identities(db: Session, device_id: str) -> dict[str, str]:
    rows = db.scalars(select(DeviceIdentity).where(DeviceIdentity.device_id == device_id))
    return {r.source: r.external_id for r in rows}


def _strong_matches(db: Session, obs: ReconcileObservation) -> list[tuple[str, str]]:
    """(kind, device_id) pairs in priority order: vendor ids first, then MAC."""
    matches: list[tuple[str, str]] = []
    for source, ext in sorted(obs.identifiers.items()):
        owner = _identity_owner(db, source, ext)
        if owner:
            matches.append(("identifier", owner))
    if obs.mac:
        owner = _identity_owner(db, "mac", obs.mac)
        if owner is None:
            # Rows older than the identity table may only carry Device.mac.
            legacy = list(db.scalars(select(Device.id).where(Device.mac == obs.mac)))
            owner = legacy[0] if len(legacy) == 1 else None
        if owner:
            matches.append(("mac", owner))
    return matches


def _compatible(db: Session, dev: Device, obs: ReconcileObservation) -> bool:
    """False when anything strong or explicit contradicts a weak IP match."""
    if obs.mac and dev.mac and obs.mac != dev.mac:
        return False
    if obs.identifiers:
        existing = _identities(db, dev.id)
        for source, ext in obs.identifiers.items():
            if source in existing and existing[source] != ext:
                return False
    if (
        obs.hostname
        and not _is_placeholder_hostname(dev, db)
        and obs.hostname.lower() != dev.hostname.strip().lower()
    ):
        return False
    return True


IpIndex = dict[str, dict[str, Device]]


def build_ip_index(db: Session) -> IpIndex:
    """One pass over devices: ip -> {device_id: Device} (batch callers)."""
    index: IpIndex = {}
    for dev in db.scalars(select(Device)):
        index_device(index, dev)
    return index


def index_device(index: IpIndex, dev: Device) -> None:
    for ip in _device_ips(dev):
        index.setdefault(ip, {})[dev.id] = dev


def _devices_with_ips(
    db: Session, ips: list[str], ip_index: IpIndex | None = None
) -> list[Device]:
    wanted = set(ips)
    if not wanted:
        return []
    if ip_index is not None:
        found: dict[str, Device] = {}
        for ip in wanted:
            found.update(ip_index.get(ip, {}))
        return list(found.values())
    return [d for d in db.scalars(select(Device)) if wanted & set(_device_ips(d))]


def _resolve(
    db: Session, obs: ReconcileObservation, ip_index: IpIndex | None = None
) -> tuple[Device | None, str, list[dict[str, Any]]]:
    """Return (device or None to create, matched_by, conflicts). Writes nothing."""
    conflicts: list[dict[str, Any]] = []
    strong = _strong_matches(db, obs)
    if strong:
        kind, primary_id = strong[0]
        for other_kind, other_id in strong[1:]:
            if other_id != primary_id:
                conflicts.append(
                    {"type": "identity_conflict", "kind": other_kind, "device_id": other_id}
                )
        return db.get(Device, primary_id), kind, conflicts

    has_strong_key = bool(obs.mac or obs.identifiers)
    holders = _devices_with_ips(db, obs.ip, ip_index)
    if len(holders) == 1:
        if _compatible(db, holders[0], obs):
            return holders[0], "ip", conflicts
        conflicts.append(
            {
                "type": "ip_held_by_other_device",
                "device_id": holders[0].id,
                "detail": "address is held by a device the evidence contradicts; not merged",
            }
        )
        return None, "new", conflicts
    if len(holders) > 1:
        if not has_strong_key:
            raise AmbiguousObservation("IP address matches more than one device")
        conflicts.append(
            {"type": "ip_held_by_multiple_devices", "device_ids": sorted(d.id for d in holders)}
        )
        return None, "new", conflicts

    if not obs.ip and not has_strong_key and obs.hostname:
        named = [
            d
            for d in db.scalars(select(Device))
            if (d.hostname or "").strip().lower() == obs.hostname.lower()
        ]
        if len(named) > 1:
            raise AmbiguousObservation("hostname matches more than one device")
        if len(named) == 1 and _compatible(db, named[0], obs):
            return named[0], "hostname", conflicts
    return None, "new", conflicts


def _clamp(value: datetime | None, now: datetime) -> datetime:
    if value is None:
        return now
    return min(value, now + FUTURE_SKEW) if value > now + FUTURE_SKEW else value


def _open_ports(dev: Device) -> set[tuple[str, int]]:
    """(proto, port) pairs on the device that are not known-closed/filtered."""
    raw = (dev.ports or {}).get("v", [])
    if not isinstance(raw, list):
        return set()
    return {(p.get("proto", "tcp"), p["port"]) for p in raw
            if isinstance(p, dict) and isinstance(p.get("port"), int)
            and p.get("state") in (None, "open")}


def _merge_ports(dev: Device, ports: list[Port]) -> bool:
    raw = (dev.ports or {}).get("v", [])
    current = list(raw) if isinstance(raw, list) else []
    known = {(p.get("proto"), p.get("port")) for p in current if isinstance(p, dict)}
    changed = False
    for p in ports:
        if p.state not in (None, "open") or (p.proto, p.port) in known:
            continue
        if len(current) >= MAX_PORTS_PER_DEVICE:
            break
        current.append(p.model_dump())
        known.add((p.proto, p.port))
        changed = True
    if changed:
        dev.ports = {"v": current}
    return changed


def _bind_identities(
    db: Session, dev: Device, obs: ReconcileObservation, conflicts: list[dict[str, Any]]
) -> list[str]:
    """Attach unclaimed strong identities; never steal or replace one."""
    applied: list[str] = []
    existing = _identities(db, dev.id)
    wanted = dict(obs.identifiers)
    if obs.mac:
        wanted["mac"] = obs.mac
    for source, ext in sorted(wanted.items()):
        if source in existing:
            if existing[source] != ext:
                conflicts.append(
                    {
                        "type": "identifier_mismatch",
                        "source": source,
                        "kept": existing[source],
                        "reported": ext,
                    }
                )
            continue
        owner = _identity_owner(db, source, ext)
        if owner is not None and owner != dev.id:
            continue  # already reported as identity_conflict in _resolve
        db.add(DeviceIdentity(id=new_id(), device_id=dev.id, source=source, external_id=ext))
        applied.append(f"identity:{source}")
    return applied


def _identity_dispute(
    db: Session,
    dev: Device,
    obs: ReconcileObservation,
    conflicts: list[dict[str, Any]],
) -> bool:
    """Quarantine conflicting identity evidence before any canonical mutation.

    The observation remains inspectable, but no IP, port, last_seen,
    hardware attribute or new identity may be attached to the matched asset.
    """
    disputed = any(c["type"] == "identity_conflict" for c in conflicts)
    if obs.mac and dev.mac and obs.mac != dev.mac:
        conflicts.append(
            {"type": "field_conflict", "field": "mac", "kept": dev.mac, "reported": obs.mac}
        )
        disputed = True
    existing = _identities(db, dev.id)
    for source, ext in obs.identifiers.items():
        if source in existing and existing[source] != ext:
            conflicts.append(
                {
                    "type": "identifier_mismatch",
                    "source": source,
                    "kept": existing[source],
                    "reported": ext,
                }
            )
            disputed = True
    return disputed


def _apply(
    db: Session,
    dev: Device,
    obs: ReconcileObservation,
    observed_at: datetime,
    conflicts: list[dict[str, Any]],
) -> list[str]:
    """Merge non-curated facts into ``dev``; returns the fields that changed."""
    applied: list[str] = []

    ips = _device_ips(dev)
    added = [ip for ip in obs.ip if ip not in ips]
    if added and len(ips) < MAX_IPS_PER_DEVICE:
        dev.ip = {"v": (ips + added)[:MAX_IPS_PER_DEVICE]}
        applied.append("ip")

    if obs.mac:
        if not dev.mac:
            owner = _identity_owner(db, "mac", obs.mac)
            if owner in (None, dev.id):
                dev.mac = obs.mac
                applied.append("mac")
        elif dev.mac != obs.mac:
            conflicts.append(
                {"type": "field_conflict", "field": "mac", "kept": dev.mac, "reported": obs.mac}
            )

    if obs.hostname and _is_placeholder_hostname(dev, db):
        dev.hostname = obs.hostname
        applied.append("hostname")

    for name in _HARDWARE_FIELDS:
        reported = getattr(obs, name)
        if not reported:
            continue
        current = getattr(dev, name)
        if not current:
            setattr(dev, name, reported)
            applied.append(name)
        elif current != reported:
            conflicts.append(
                {"type": "field_conflict", "field": name, "kept": current, "reported": reported}
            )

    if _merge_ports(dev, obs.ports):
        applied.append("ports")

    if dev.first_seen is None or observed_at < dev.first_seen:
        dev.first_seen = observed_at
        applied.append("first_seen")
    if dev.last_seen is None or observed_at > dev.last_seen:
        dev.last_seen = observed_at
        applied.append("last_seen")
    if dev.discovery_method is None:
        dev.discovery_method = obs.source
        applied.append("discovery_method")
    return applied


def _observation_data(
    obs: ReconcileObservation, matched_by: str, applied: list[str], conflicts: list[dict]
) -> dict:
    data: dict[str, Any] = {}
    for name in ("hostname", "mac", "vendor", "model", "os", "serial"):
        value = getattr(obs, name)
        if value:
            data[name] = value
    if obs.ip:
        data["ip"] = list(obs.ip)
    if obs.identifiers:
        data["identifiers"] = dict(obs.identifiers)
    if obs.ports:
        data["ports"] = [p.model_dump() for p in obs.ports]
    if obs.data:
        data["extra"] = obs.data
    data["reconciliation"] = {
        "matched_by": matched_by,
        "applied_fields": applied,
        "conflicts": conflicts,
    }
    return data


def _find_row(db: Session, device_id: str, obs: ReconcileObservation) -> DeviceObservation | None:
    ref_clause = (
        DeviceObservation.source_ref == obs.source_ref
        if obs.source_ref is not None
        else DeviceObservation.source_ref.is_(None)
    )
    return db.scalar(
        select(DeviceObservation)
        .where(
            DeviceObservation.device_id == device_id,
            DeviceObservation.source == obs.source,
            ref_clause,
        )
        .order_by(DeviceObservation.observed_at.desc())
        .limit(1)
    )


# -- public API ------------------------------------------------------------


def reconcile_observation(
    db: Session, obs: ReconcileObservation, *, ip_index: IpIndex | None = None
) -> ReconcileResult:
    """Match ``obs`` to an existing device or create one, then merge safely.

    Raises ``AmbiguousObservation`` (before any write) when only weak evidence
    is available and it matches several devices. A caller-supplied ``ip_index``
    (see ``build_ip_index``) is kept current with the device touched here.
    """
    now = datetime.now(UTC)
    observed_at = _clamp(obs.observed_at, now)
    dev, matched_by, conflicts = _resolve(db, obs, ip_index)

    created = dev is None
    if dev is None:
        name = obs.hostname or (obs.ip[0] if obs.ip else None) or obs.mac
        name = name or next(iter(obs.identifiers.values()))
        dev = Device(
            id=new_id(),
            hostname=name,
            ip={"v": []},
            roles={"v": []},
            ports={"v": []},
        )
        db.add(dev)
        db.flush()

    # Strong identities may select a device while contradicting its other
    # identity evidence. Preserve that report, but never contaminate inventory.
    disputed = _identity_dispute(db, dev, obs, conflicts)
    prior = None if created else _find_row(db, dev.id, obs)
    if prior is not None and observed_at < prior.observed_at:
        # Stale: older than what this source already told us. Only history
        # (first_seen) may legitimately move; the stored row stays as is.
        applied: list[str] = []
        if not disputed and (dev.first_seen is None or observed_at < dev.first_seen):
            dev.first_seen = observed_at
            applied.append("first_seen")
        db.flush()
        return ReconcileResult(
            device_id=dev.id,
            observation_id=prior.id,
            action="merged",
            matched_by=matched_by,
            stale=True,
            applied_fields=applied,
            conflicts=conflicts,
        )

    ips_before = set() if created else set(_device_ips(dev))
    ports_before = set() if created else _open_ports(dev)
    applied = [] if disputed else _apply(db, dev, obs, observed_at, conflicts)
    if not disputed:
        if created:
            events.on_device_created(db, dev.id, obs.source, dev.hostname, observed_at)
        else:
            events.on_addresses_added(
                db, dev.id, sorted(set(_device_ips(dev)) - ips_before), observed_at)
            events.on_ports_opened(db, dev.id, sorted(_open_ports(dev) - ports_before), observed_at)
    if not disputed:
        applied += _bind_identities(db, dev, obs, conflicts)
    data = _observation_data(obs, matched_by, applied, conflicts)
    data["reconciliation"]["quarantined"] = disputed
    if prior is None:
        prior = DeviceObservation(
            id=new_id(),
            device_id=dev.id,
            source=obs.source,
            source_ref=obs.source_ref,
            observed_at=observed_at,
            data=data,
        )
        db.add(prior)
    else:
        prior.observed_at = observed_at
        prior.data = data
    db.flush()
    if not disputed:
        evidence = health.source_for_observation(obs.source, obs.data)
        if evidence is not None:
            source, ok, authoritative = evidence
            health.record(db, dev.id, source, ok, observed_at, authoritative=authoritative)
    if ip_index is not None:
        index_device(ip_index, dev)
    return ReconcileResult(
        device_id=dev.id,
        observation_id=prior.id,
        action="created" if created else "merged",
        matched_by=matched_by,
        applied_fields=applied,
        conflicts=conflicts,
    )


def _parse_time(value: object) -> datetime | None:
    if isinstance(value, str):
        try:
            return ensure_utc(datetime.fromisoformat(value))
        except ValueError:
            return None
    return None


def persist_icmp_scan_result(db: Session, job_id: str, result: dict) -> None:
    """Reconcile responsive ICMP hosts as IP-only (weak) sightings.

    A responsive address attaches to its unique, non-contradicting holder or
    becomes a new placeholder asset; ambiguous or invalid entries are counted
    and skipped. Unanswered addresses are never treated as offline evidence.
    """
    if result.get("probe") != "icmp_echo":
        return
    counts = {"created": 0, "merged": 0, "ambiguous": 0, "invalid": 0}
    responsive_ids: set[str] = set()
    hosts = result.get("hosts", [])
    # Built once per result instead of one full Device scan per host.
    ip_index = build_ip_index(db) if hosts else {}
    for raw in hosts:
        if not isinstance(raw, dict):
            counts["invalid"] += 1
            continue
        try:
            obs = ReconcileObservation(
                source="scan",
                source_ref="icmp-echo",
                observed_at=_parse_time(raw.get("observed_at")),
                ip=[str(raw.get("ip"))],
                data={"probe": "icmp_echo", "job_id": job_id},
            )
            outcome = reconcile_observation(db, obs, ip_index=ip_index)
        except (ValidationError, ValueError):
            counts["invalid"] += 1
            continue
        except AmbiguousObservation:
            counts["ambiguous"] += 1
            continue
        counts[outcome.action] += 1
        responsive_ids.add(outcome.device_id)
    result["asset_reconciliation"] = counts
    result["health"] = {"icmp_unanswered": health.record_icmp_misses(db, job_id, responsive_ids)}


def persist_scan_result(db: Session, job_id: str, result: dict) -> None:
    """Worker hook: route a finished scan result to its persister."""
    persist_tcp_scan_result(db, job_id, result)
    persist_icmp_scan_result(db, job_id, result)
