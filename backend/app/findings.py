"""Finding persistence, deduplication and lifecycle (M18, issue #21).

* Identity: ``sha256(device | template | scheme | port | matcher | path)``. The same issue
  found again updates one row (``last_seen``, ``occurrences``); it never duplicates.
* Lifecycle: ``open`` -> ``resolved`` (a *complete* later run of the same template on the
  same URL no longer reports it) -> ``open`` again if it reappears; ``suppressed`` is an
  explicit operator decision that reruns never override (only ``last_seen`` advances).
* Every transition appends to ``finding_events`` (capped), preserving the rerun audit trail.
* Only sanitized fields are stored; ``clean``/``redact`` is applied again here, so a bug in
  an upstream parser cannot leak secrets into the database or API.
Callers own the transaction; nothing here commits.
"""
from __future__ import annotations

import hashlib
import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import events
from .models import Device, Finding, FindingEvent
from .redaction import clean

SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")
STATUSES = ("open", "resolved", "suppressed")
MAX_EVENTS_PER_FINDING = 200
ALERT_SEVERITIES = {"medium", "high", "critical"}


def fingerprint(device_id: str, f: dict[str, Any]) -> str:
    parts = (device_id, f["template_id"], f["scheme"], str(f["port"]),
             f.get("matcher_name") or "", f.get("path") or "/")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _add_event(db: Session, finding: Finding, type_: str, when: datetime, *,
               job_id: str | None = None, actor: str | None = None,
               note: str | None = None) -> None:
    db.add(FindingEvent(id=str(uuid.uuid4()), finding_id=finding.id, at=when, type=type_,
                        job_id=job_id, actor=actor, note=(note or "")[:300] or None))
    db.flush()
    old = db.scalars(select(FindingEvent.id).where(FindingEvent.finding_id == finding.id)
                     .order_by(FindingEvent.at.desc(), FindingEvent.id.desc())
                     .offset(MAX_EVENTS_PER_FINDING).limit(500)).all()
    for ident in old:
        db.delete(db.get(FindingEvent, ident))


def _details(f: dict[str, Any]) -> dict[str, Any]:
    def texts(values: Any, limit: int, count: int) -> list[str]:
        items = values if isinstance(values, list) else []
        return [t for t in (clean(v, limit) for v in items[:count]) if t]

    return {"description": clean(f.get("description"), 500), "tags": texts(f.get("tags"), 40, 10),
            "cve": texts(f.get("cve"), 32, 5), "cwe": texts(f.get("cwe"), 32, 5),
            "evidence": texts(f.get("evidence"), 200, 5), "type": clean(f.get("type"), 16)}


def _device_for(db: Session, host: str) -> Device | None:
    """The single device holding this address; ambiguity or absence means no match."""
    try:
        wanted = str(ipaddress.IPv4Address(host))
    except ValueError:
        return None
    matches = [d for d in db.scalars(select(Device))
               if wanted in (d.ip or {}).get("v", [])]
    return matches[0] if len(matches) == 1 else None


def persist_nuclei_result(db: Session, job_id: str, result: dict) -> None:
    """Worker hook for ``probe == "nuclei"`` results; adds a ``finding_persistence`` summary."""
    if result.get("probe") != "nuclei":
        return
    now = datetime.now(UTC)
    versions = result.get("versions") or {}
    summary = {"created": 0, "updated": 0, "reopened": 0, "resolved": 0, "unmatched": 0}
    seen_fingerprints: dict[str, set[str]] = {}
    # Everything the scanner reported, whatever happens to it below (unmatched/ambiguous
    # hosts included): it must never be auto-resolved, and it proves the service answered.
    reported: set[tuple[str, int, str]] = set()
    reached: set[tuple[str, int]] = set()
    for f in result.get("findings") or []:
        if isinstance(f, dict) and f.get("template_id") and f.get("host"):
            port = int(f.get("port") or 0)
            reported.add((str(f["host"]), port, clean(f["template_id"], 128) or "unknown"))
            reached.add((str(f["host"]), port))
    for f in result.get("findings") or []:
        if not isinstance(f, dict) or not f.get("template_id") or not f.get("host"):
            continue
        sev = f.get("severity") if f.get("severity") in SEVERITIES else "unknown"
        device = _device_for(db, str(f["host"]))
        if device is None:
            summary["unmatched"] += 1
            continue
        f = {**f, "path": clean(f.get("path"), 200) or "/",
             "scheme": f.get("scheme") if f.get("scheme") in ("http", "https") else "http",
             "port": int(f.get("port") or 0), "matcher_name": clean(f.get("matcher_name"), 100),
             "template_id": clean(f["template_id"], 128) or "unknown"}
        fp = fingerprint(device.id, f)
        seen_fingerprints.setdefault(device.id, set()).add(fp)
        row = db.scalar(select(Finding).where(Finding.device_id == device.id,
                                              Finding.fingerprint == fp))
        if row is None:
            row = Finding(
                id=str(uuid.uuid4()), device_id=device.id, fingerprint=fp,
                template_id=f["template_id"], name=clean(f.get("name"), 200) or f["template_id"],
                severity=sev, status="open", host=str(f["host"])[:64], port=f["port"],
                scheme=f["scheme"], path=f["path"], matcher_name=f["matcher_name"],
                first_seen=now, last_seen=now, occurrences=1, last_job_id=job_id,
                template_version=versions.get("templates"), scanner_version=versions.get("nuclei"),
                details=_details(f))
            db.add(row)
            db.flush()
            _add_event(db, row, "opened", now, job_id=job_id)
            summary["created"] += 1
            if sev in ALERT_SEVERITIES:
                events.on_finding_opened(db, device.id, row.id, row.name, sev, now)
            continue
        row.last_seen, row.occurrences, row.last_job_id = now, row.occurrences + 1, job_id
        row.template_version = versions.get("templates") or row.template_version
        row.scanner_version = versions.get("nuclei") or row.scanner_version
        row.severity, row.details = sev, _details(f)
        if row.status == "resolved":
            row.status, row.resolved_at = "open", None
            _add_event(db, row, "reopened", now, job_id=job_id)
            summary["reopened"] += 1
        else:
            _add_event(db, row, "seen", now, job_id=job_id)
            summary["updated"] += 1
    summary["resolved"] = _resolve_absent(db, job_id, result, seen_fingerprints, reported,
                                          reached, now)
    result["finding_persistence"] = summary


def _resolve_absent(db: Session, job_id: str, result: dict, seen: dict[str, set[str]],
                    reported: set[tuple[str, int, str]], reached: set[tuple[str, int]],
                    now: datetime) -> int:
    """Resolve open findings a *trustworthy, complete* rerun covered but did not report.

    Resolution needs positive evidence that the service was actually checked: at least one
    result from the same host:port in this run (a down host, or one Nuclei stopped probing
    after repeated errors, produces none and is left untouched). Any parse failure,
    truncation, time-out or over-limit drop makes the whole run inconclusive."""
    counters = result.get("counters") or {}
    if (result.get("timed_out") or result.get("output_truncated")
            or counters.get("dropped_over_limit") or counters.get("invalid")):
        return 0
    templates = set(result.get("templates") or [])
    scanned: set[tuple[str, int]] = set()
    for url in result.get("urls") or []:
        parts = urlsplit(str(url))
        if parts.hostname and parts.port:
            scanned.add((parts.hostname, parts.port))
    resolved = 0
    for row in db.scalars(select(Finding).where(Finding.status == "open")):
        key = (row.host, row.port)
        if key not in scanned or key not in reached:
            continue
        if row.fingerprint in seen.get(row.device_id, ()) \
                or (row.host, row.port, row.template_id) in reported:
            continue
        # Template ids differ from file names; only resolve when the run covered this template.
        if not any(t.rsplit("/", 1)[-1].removesuffix(".yaml") == row.template_id
                   for t in templates):
            continue
        row.status, row.resolved_at = "resolved", now
        _add_event(db, row, "resolved", now, job_id=job_id, note="not reported by a complete rerun")
        resolved += 1
    return resolved


def set_suppressed(db: Session, row: Finding, suppressed: bool, actor: str,
                   reason: str | None = None) -> Finding:
    now = datetime.now(UTC)
    if suppressed and row.status != "suppressed":
        row.status, row.suppressed_reason = "suppressed", (clean(reason, 300) or "suppressed")
        _add_event(db, row, "suppressed", now, actor=actor, note=row.suppressed_reason)
    elif not suppressed and row.status == "suppressed":
        row.status, row.suppressed_reason = "open", None
        _add_event(db, row, "unsuppressed", now, actor=actor)
    return row
