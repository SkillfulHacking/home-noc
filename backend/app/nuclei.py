"""Nuclei vulnerability profile runner (M17, issue #20).

Safety model (every point is covered by tests):
* **Opt-in and approved.** The ``vuln`` profile is disabled unless
  ``SCAN_VULN_PROFILE_ENABLED`` is set, and a job only runs if the operator
  approved the exact plan (targets + templates + versions) by its digest.
* **No target expansion.** Only ``http(s)://<authorized-ip>:<port>`` URLs built from
  open HTTP ports *already recorded* for a device holding that authorized address.
  Hostnames, redirects and CIDR sweeps are never used; findings for any other host
  are discarded.
* **Curated templates.** An explicit allowlist of read-only HTTP templates; missing or
  symlinked files are excluded and reported. Dangerous tags/protocols are excluded and
  interactsh/OAST (``-ni``) and update checks (``-duc``) are off.
* **Bounded.** Rate/concurrency/timeout limits, one process group that cancellation or
  the deadline kills, output size and finding count caps, minimal environment.
* **Sanitized.** Raw requests/responses/curl commands are never kept; text is redacted.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import subprocess
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import Device
from .redaction import clean
from .scan_runner import (
    POLL_SECONDS,
    JobContext,
    RunnerError,
    _Authorizer,
    _killpg,
    _scanner_env,
    stop_process_group,
)
from .scan_scope import PROFILES, ScanProfile

logger = logging.getLogger("home_noc.nuclei")

# Curated, read-only HTTP templates (paths relative to the pinned templates dir).
SAFE_TEMPLATES: tuple[str, ...] = (
    "http/technologies/tech-detect.yaml",
    "http/technologies/favicon-detect.yaml",
    "http/misconfiguration/http-missing-security-headers.yaml",
    "http/misconfiguration/directory-listing-no-host-header.yaml",
    "http/misconfiguration/php-errors.yaml",
    "http/exposures/configs/git-config.yaml",
    "http/exposures/files/ds-store-file.yaml",
)
EXCLUDED_TAGS = ("dos", "fuzz", "intrusive", "bruteforce", "brute-force", "rce", "sqli", "xss",
                 "dast", "oast", "default-login", "takeover")
HTTP_PORTS = {80: "http", 8000: "http", 8080: "http", 8888: "http", 443: "https", 8443: "https"}
MAX_URLS = 64
MAX_FINDINGS = 500
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")
# Single source of truth for the shipped versions; backend/Dockerfile ARGs must match
# (enforced by a test). The worker refuses to run if the installed versions differ.
PINNED = {"nuclei": "3.11.1", "templates": "10.5.2"}


# ---------------------------------------------------------------- planning ---

def read_versions() -> dict[str, str | None]:
    """Pinned nuclei/templates versions written at image build time (None if unknown)."""
    try:
        data = json.loads(Path(settings.nuclei_versions_file).read_text())
        return {"nuclei": str(data.get("nuclei"))[:32] or None,
                "templates": str(data.get("templates"))[:32] or None}
    except (OSError, ValueError, AttributeError):
        return {"nuclei": None, "templates": None}


def usable_templates(root: Path | None = None) -> tuple[list[str], list[str]]:
    """(usable, excluded) from the allowlist: regular files inside the templates dir only."""
    base = (root or Path(settings.nuclei_templates_dir))
    usable, excluded = [], []
    for rel in SAFE_TEMPLATES:
        path = base / rel
        try:
            ok = path.is_file() and not path.is_symlink() and \
                path.resolve().is_relative_to(base.resolve())
        except OSError:
            ok = False
        (usable if ok else excluded).append(rel)
    return usable, excluded


def _http_urls(db: Session, networks: list[ipaddress.IPv4Network]) -> list[str]:
    urls: list[str] = []
    for device in db.scalars(select(Device).order_by(Device.id)):
        ports = {p["port"] for p in (device.ports or {}).get("v", [])
                 if isinstance(p, dict) and p.get("proto") == "tcp" and p.get("state") == "open"
                 and isinstance(p.get("port"), int) and p["port"] in HTTP_PORTS}
        for value in (device.ip or {}).get("v", []):
            try:
                addr = ipaddress.IPv4Address(value)
            except ValueError:
                continue
            if any(addr in net for net in networks):
                urls += [f"{HTTP_PORTS[port]}://{addr}:{port}" for port in sorted(ports)]
    return sorted(set(urls))[:MAX_URLS]


def build_plan(db: Session, networks: list[ipaddress.IPv4Network]) -> dict[str, Any]:
    """The plan the operator approves. It must be computed identically by the API and the
    worker, which see different filesystems, so the digest covers only data that does not
    depend on the container: URLs, networks, the template allowlist, the pinned versions and
    fixed limits. What is actually installed is verified by the worker at run time."""
    urls = _http_urls(db, networks)
    body = {"urls": urls, "templates": list(SAFE_TEMPLATES), "versions": dict(PINNED),
            "networks": sorted(str(n) for n in networks),
            "fixed_limits": {"timeout_seconds": PROFILES[ScanProfile.VULN].timeout_seconds,
                             "max_urls": MAX_URLS}}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {**body, "limits": limits(), "approval_digest": digest}


def limits() -> dict[str, int]:
    spec = PROFILES[ScanProfile.VULN]
    return {"rate_limit": settings.nuclei_rate_limit, "concurrency": settings.nuclei_concurrency,
            "timeout_seconds": spec.timeout_seconds, "max_urls": MAX_URLS}


def build_argv(targets_file: str, templates: list[str], templates_root: str) -> list[str]:
    """Fixed argv; only generated file paths and numeric limits vary. Never a shell."""
    argv = [settings.nuclei_binary, "-l", targets_file]
    for rel in templates:
        argv += ["-t", os.path.join(templates_root, rel)]
    argv += [
        "-jsonl", "-silent", "-no-color", "-duc", "-ni", "-no-stdin", "-omit-raw",
        "-pt", "http", "-etags", ",".join(EXCLUDED_TAGS),
        "-rl", str(settings.nuclei_rate_limit), "-c", str(settings.nuclei_concurrency),
        "-timeout", "5", "-retries", "0", "-mhe", "10",
    ]
    return argv


# ------------------------------------------------------------------ parsing ---

def parse_jsonl(text: str, allowed_hosts: set[str]) -> tuple[list[dict], dict[str, int]]:
    """Parse Nuclei JSONL defensively. Returns (findings, counters)."""
    findings: list[dict] = []
    counters = {"invalid": 0, "out_of_scope": 0, "dropped_over_limit": 0}
    for line in text.splitlines():
        if not line.strip():
            continue
        if len(line) > MAX_LINE_BYTES:
            counters["invalid"] += 1
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            counters["invalid"] += 1
            continue
        finding = _finding(raw, allowed_hosts) if isinstance(raw, dict) else None
        if finding is None:
            counters["invalid"] += 1
        elif finding == "out_of_scope":
            counters["out_of_scope"] += 1
        elif len(findings) >= MAX_FINDINGS:
            counters["dropped_over_limit"] += 1
        else:
            findings.append(finding)
    return findings, counters


def _finding(raw: dict, allowed_hosts: set[str]) -> dict | str | None:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    template_id = clean(raw.get("template-id"), 128)
    matched = raw.get("matched-at") or raw.get("url")
    if not template_id or not isinstance(matched, str):
        return None
    parts = urlsplit(matched)
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or host not in allowed_hosts:
        return "out_of_scope"  # never record or follow anything outside the authorized set
    severity = str(info.get("severity", "unknown")).lower()
    tags = info.get("tags") if isinstance(info.get("tags"), list) else []
    classification = info.get("classification") if isinstance(info.get("classification"),
                                                              dict) else {}
    extracted = raw.get("extracted-results") if isinstance(raw.get("extracted-results"),
                                                           list) else []
    return {
        "template_id": template_id,
        "name": clean(info.get("name"), 200) or template_id,
        "severity": severity if severity in SEVERITIES else "unknown",
        "tags": [t for t in (clean(x, 40) for x in tags[:10]) if t],
        "description": clean(info.get("description"), 500),
        "matcher_name": clean(raw.get("matcher-name"), 100),
        "type": clean(raw.get("type"), 16),
        "host": host,
        "port": port or (443 if parts.scheme == "https" else 80),
        "scheme": parts.scheme,
        "matched_at": f"{parts.scheme}://{host}:{port}" if port else f"{parts.scheme}://{host}",
        "path": clean(parts.path, 200) or "/",
        "cve": [c for c in (clean(x, 32) for x in (classification.get("cve-id") or [])[:5]
                            if isinstance(classification.get("cve-id"), list)) if c],
        "cwe": [c for c in (clean(x, 32) for x in (classification.get("cwe-id") or [])[:5]
                            if isinstance(classification.get("cwe-id"), list)) if c],
        "evidence": [e for e in (clean(x, 200) for x in extracted[:5]) if e],
        "observed_at": clean(raw.get("timestamp"), 40),
    }


# ------------------------------------------------------------------ running ---

def run_nuclei(ctx: JobContext, session_factory: Callable[[], Session]) -> dict[str, Any]:
    if ctx.profile != ScanProfile.VULN.value:
        raise RunnerError("invalid_profile", "Not a vulnerability job", retryable=False)
    authorizer = _Authorizer(ctx, ScanProfile.VULN)
    networks = authorizer.authorize()
    check = authorizer.check
    with session_factory() as db:
        plan = build_plan(db, networks)
    if not ctx.approval or ctx.approval != plan["approval_digest"]:
        # Targets, templates or versions changed since the operator approved the plan.
        raise RunnerError("approval_stale", "The approved plan no longer matches; re-approve",
                          retryable=False)
    installed = read_versions()
    if installed != PINNED:
        raise RunnerError("version_mismatch",
                          "Installed Nuclei/template versions differ from the approved pins",
                          retryable=False)
    usable, excluded = usable_templates()
    base = {"probe": "nuclei", "profile": "vuln", "versions": installed,
            "templates": usable, "excluded_templates": excluded,
            "target_count": len(plan["urls"]), "approval_digest": plan["approval_digest"],
            "started_at": datetime.now(UTC).isoformat()}
    if not plan["urls"] or not usable:
        ctx.progress(1, 1)
        return {**base, "findings": [], "counters": {}, "timed_out": False, "note":
                "no known HTTP services or no usable templates; nothing was scanned"}

    allowed_hosts = {urlsplit(u).hostname for u in plan["urls"]}
    spec = PROFILES[ScanProfile.VULN]
    ctx.progress(0, len(plan["urls"]))
    ctx.event("plan", f"Nuclei: {len(plan['urls'])} URL(s), {len(usable)} template(s)")
    with tempfile.TemporaryDirectory(prefix="home-noc-nuclei-") as tmp:
        targets_file = os.path.join(tmp, "targets.txt")
        Path(targets_file).write_text("\n".join(plan["urls"]) + "\n")
        env = {**_scanner_env(), "HOME": tmp, "XDG_CONFIG_HOME": tmp, "XDG_CACHE_HOME": tmp}
        argv = build_argv(targets_file, usable, settings.nuclei_templates_dir)
        out_path = os.path.join(tmp, "out.jsonl")
        timed_out = False
        with open(out_path, "wb") as out:
            try:
                proc = subprocess.Popen(  # noqa: S603 - fixed argv, generated paths, no shell
                    argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL,
                    start_new_session=True, close_fds=True, shell=False, cwd=tmp, env=env)
            except FileNotFoundError:
                raise RunnerError("scanner_missing", "Nuclei is not installed in the worker image",
                                  retryable=False) from None
            except OSError:
                raise RunnerError("spawn_failed", "Could not start Nuclei", retryable=True) \
                    from None
            ctx.set_pid(proc.pid)
            deadline = time.monotonic() + spec.timeout_seconds
            try:
                while True:
                    try:
                        rc = proc.wait(timeout=POLL_SECONDS)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    if os.path.getsize(out_path) > MAX_OUTPUT_BYTES:
                        raise RunnerError("output_too_large", "Nuclei output exceeded its limit",
                                          retryable=False)
                    if time.monotonic() >= deadline:
                        timed_out = True
                        stop_process_group(proc, settings.worker_kill_grace_seconds)
                        rc = None
                        break
                    check()
            except BaseException:
                stop_process_group(proc, settings.worker_kill_grace_seconds)
                raise
            finally:
                _killpg(proc.pid, 9)
                try:
                    ctx.set_pid(None)
                except Exception:  # noqa: BLE001
                    logger.warning("could not clear runner pid", exc_info=True)
        with open(out_path, "rb") as fh:
            text = fh.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")
    if rc not in (0, None):
        raise RunnerError("scanner_failed", f"Nuclei exited with status {rc}", retryable=False)
    findings, counters = parse_jsonl(text, {h for h in allowed_hosts if h})
    ctx.progress(len(plan["urls"]), len(plan["urls"]))
    ctx.event("done", f"Nuclei finished: {len(findings)} finding(s)")
    return {**base, "findings": findings, "counters": counters, "timed_out": timed_out,
            "finished_at": datetime.now(UTC).isoformat()}

