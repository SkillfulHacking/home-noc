"""Scan execution for the worker (M09/M10, issues #12/#13).

ICMP discovery uses a low-privilege datagram ping socket with bounded in-flight
probes. Nmap profiles run as children in their **own session/process group**
with fixed argv lists (never a shell, never operator-supplied flags). Stopping
a job -- cancel, timeout, lost lease or worker shutdown -- closes the socket or
signals the whole process group, so no scanner can outlive the job.

Targets are re-validated against the *current* authorized scope immediately
before running (the scope may have changed since the job was queued), and are
split into small chunks so progress is real and a stop request is honoured
between and during chunks.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from .config import settings
from .icmp_scanner import (
    IcmpDeadlineExceeded,
    IcmpScanner,
    IcmpUnavailable,
    expand_targets,
)
from .scan_scope import (
    PROFILES,
    ProfileSpec,
    ScanProfile,
    ScopeError,
    check_profile_enabled,
    resolve_targets,
)

logger = logging.getLogger("home_noc.scan_runner")

CHUNK_PREFIX = 27            # at most 32 addresses per scanner invocation
POLL_SECONDS = 0.25          # how often a running scanner is checked
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_RESULT_HOSTS = 1024


class JobStopped(Exception):
    """The job must stop now. ``reason``: cancel | lost | shutdown."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class RunnerError(Exception):
    """A classified failure. ``message`` is stored and shown to the operator,
    so it must never contain secrets or raw exception text."""

    def __init__(self, code: str, message: str, *, retryable: bool):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


@dataclass
class JobContext:
    """What an executor may do; the worker wires these to the database."""

    job_id: str
    profile: str
    targets: list[str]
    attempt: int
    check: Callable[[], None]                   # raises JobStopped
    progress: Callable[[int, int], None]        # (done, total) in addresses
    event: Callable[[str, str], None]           # (type, message)
    set_pid: Callable[[int | None], None]


# ------------------------------------------------------------- planning

def plan_chunks(networks: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    chunks: list[ipaddress.IPv4Network] = []
    for net in networks:
        if net.prefixlen >= CHUNK_PREFIX:
            chunks.append(net)
        else:
            chunks.extend(net.subnets(new_prefix=CHUNK_PREFIX))
    return chunks


def build_argv(spec: ProfileSpec, chunk: ipaddress.IPv4Network) -> list[str]:
    if spec.name == ScanProfile.DISCOVERY:
        raise ValueError("ICMP discovery does not use nmap")
    # -n: never resolve names. Everything but the validated network is fixed.
    return [
        settings.scan_nmap_binary,
        "-n",
        *spec.argv,
        "--max-parallelism",
        str(spec.max_concurrency),
        "-oG",
        "-",
        "--",
        str(chunk),
    ]


def parse_grepable(text: str) -> dict[str, list[int]]:
    """Parse nmap ``-oG`` output into ``{ip: [open ports]}`` for hosts that are up."""
    hosts: dict[str, list[int]] = {}
    for line in text.splitlines():
        if not line.startswith("Host: "):
            continue
        parts = line.split("\t")
        head = parts[0].split()
        if len(head) < 2:
            continue
        try:
            ip = str(ipaddress.IPv4Address(head[1]))
        except ValueError:
            continue
        fields = {}
        for part in parts[1:]:
            key, sep, value = part.partition(":")
            if sep:
                fields[key.strip()] = value.strip()
        if "Ports" not in fields and not fields.get("Status", "").startswith("Up"):
            continue
        ports = hosts.setdefault(ip, [])
        for entry in fields.get("Ports", "").split(","):
            bits = entry.strip().split("/")
            if len(bits) > 1 and bits[0].isdigit() and bits[1] == "open":
                port = int(bits[0])
                if port not in ports:
                    ports.append(port)
    return hosts


# ------------------------------------------------------- process control

def _killpg(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def stop_process_group(proc: subprocess.Popen, grace: float) -> None:
    """SIGTERM the group, escalate to SIGKILL after ``grace``, then sweep any
    stragglers. Safe to call repeatedly."""
    pgid = proc.pid  # the child is its own group leader (start_new_session)
    _killpg(pgid, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        _killpg(pgid, signal.SIGKILL)
        proc.wait()
    # The leader may be gone while a descendant is not.
    _killpg(pgid, signal.SIGKILL)


def reap_stale_process_group(pid: int | None) -> bool:
    """Kill a scanner group left by a previous incarnation of *this* worker.

    Pid reuse is guarded: the pid must still be its own group leader and its
    command line must contain the configured scanner binary name. Never
    touches our own group.
    """
    if not pid or pid <= 1:
        return False
    try:
        if pid == os.getpgrp() or os.getpgid(pid) != pid:
            return False
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            argv = [a for a in fh.read().split(b"\0") if a]
    except OSError:
        return False
    expected = {os.path.basename(settings.scan_nmap_binary)}
    if not any(os.path.basename(a.decode(errors="replace")) in expected for a in argv[:3]):
        return False
    _killpg(pid, signal.SIGKILL)
    logger.warning("reaped stale scanner process group %d", pid)
    return True


def _scanner_env() -> dict[str, str]:
    # Deliberately minimal: the scanner never sees application secrets.
    return {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LC_ALL": "C"}


def _run_chunk(
    ctx: JobContext, spec: ProfileSpec, chunk: ipaddress.IPv4Network, time_left: float,
) -> str:
    argv = build_argv(spec, chunk)
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, validated target, no shell
                argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL,
                start_new_session=True, close_fds=True, shell=False, cwd="/",
                env=_scanner_env(),
            )
        except FileNotFoundError:
            raise RunnerError(
                "scanner_missing", "Scanner executable not found in the worker image",
                retryable=False,
            ) from None
        except OSError:
            raise RunnerError(
                "spawn_failed", "Could not start the scanner", retryable=True
            ) from None

        ctx.set_pid(proc.pid)
        deadline = time.monotonic() + time_left
        try:
            while True:
                try:
                    rc = proc.wait(timeout=POLL_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() >= deadline:
                    raise RunnerError("timeout", "Scan exceeded its time limit", retryable=False)
                ctx.check()
        except BaseException:
            stop_process_group(proc, settings.worker_kill_grace_seconds)
            raise
        finally:
            _killpg(proc.pid, signal.SIGKILL)  # sweep descendants after a normal exit too
            try:
                ctx.set_pid(None)
            except Exception:  # noqa: BLE001 - never mask the real outcome
                logger.warning("could not clear runner pid", exc_info=True)

        if rc != 0:
            raise RunnerError(
                "scanner_failed", f"Scanner exited with status {rc}", retryable=True
            )
        out.seek(0)
        return out.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")


def run_scan(ctx: JobContext) -> dict:
    """Execute one scan job; returns a result summary or raises."""
    try:
        profile = ScanProfile(ctx.profile)
    except ValueError:
        raise RunnerError("invalid_profile", "Unknown scan profile", retryable=False) from None
    try:
        # Authorization is re-checked at execution time, not only at enqueue.
        check_profile_enabled(profile)
        networks, _ = resolve_targets(ctx.targets, profile)
    except ScopeError as exc:
        raise RunnerError("scope_rejected", exc.message, retryable=False) from None

    spec = PROFILES[profile]
    if profile == ScanProfile.DISCOVERY:
        return _run_icmp_discovery(ctx, spec, networks)

    chunks = plan_chunks(networks)
    total = sum(c.num_addresses for c in chunks)
    ctx.progress(0, total)
    ctx.event("plan", f"Scanning {len(chunks)} chunk(s), {total} address(es)")

    deadline = time.monotonic() + spec.timeout_seconds
    done = 0
    found: dict[str, list[int]] = {}
    for index, chunk in enumerate(chunks, start=1):
        ctx.check()
        time_left = deadline - time.monotonic()
        if time_left <= 0:
            raise RunnerError("timeout", "Scan exceeded its time limit", retryable=False)
        hosts = parse_grepable(_run_chunk(ctx, spec, chunk, time_left))
        found.update(hosts)
        done += chunk.num_addresses
        ctx.progress(done, total)
        ctx.event("chunk_done", f"Chunk {index}/{len(chunks)} {chunk}: {len(hosts)} host(s) up")

    listed = sorted(found, key=ipaddress.IPv4Address)[:MAX_RESULT_HOSTS]
    return {
        "profile": profile.value,
        "chunks": len(chunks),
        "hosts_up": len(found),
        "hosts": [{"ip": ip, "open_ports": sorted(found[ip])} for ip in listed],
        "truncated": len(found) > len(listed),
    }


def _run_icmp_discovery(
    ctx: JobContext, spec: ProfileSpec, networks: list[ipaddress.IPv4Network]
) -> dict:
    targets = expand_targets(networks)
    started = datetime.now(UTC)
    deadline = time.monotonic() + spec.timeout_seconds
    ctx.event(
        "plan",
        f"ICMP echo discovery of {len(targets)} address(es); "
        f"at most {spec.max_concurrency} probe(s) in flight",
    )
    scanner = IcmpScanner(
        max_concurrency=spec.max_concurrency,
        probe_timeout=settings.scan_icmp_probe_timeout_seconds,
        poll_interval=POLL_SECONDS,
    )
    try:
        result = scanner.scan(
            targets, deadline=deadline, check=ctx.check, progress=ctx.progress
        )
    except IcmpDeadlineExceeded:
        raise RunnerError("timeout", "Scan exceeded its time limit", retryable=False) from None
    except IcmpUnavailable:
        raise RunnerError(
            "icmp_unavailable",
            "ICMP echo probing is not permitted in the worker runtime",
            retryable=False,
        ) from None

    finished = datetime.now(UTC)
    hosts = [
        {"ip": host.ip, "responsive": True, "observed_at": host.observed_at.isoformat()}
        for host in result.responsive[:MAX_RESULT_HOSTS]
    ]
    ctx.event(
        "discovery_done",
        f"ICMP discovery completed: {len(result.responsive)} responsive, "
        f"{result.unanswered} unanswered (inconclusive)",
    )
    return {
        "profile": ScanProfile.DISCOVERY.value,
        "probe": "icmp_echo",
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "attempted": result.attempted,
        # Kept for API compatibility with M09 results. This means a positive
        # ICMP response only; unanswered addresses are never labelled down.
        "hosts_up": len(result.responsive),
        "hosts": hosts,
        "unanswered": result.unanswered,
        "unanswered_status": "inconclusive",
        "truncated": len(result.responsive) > len(hosts),
    }
