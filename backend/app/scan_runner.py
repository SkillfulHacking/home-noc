"""Scan execution for the worker (M09-M11, issues #12-#14).

ICMP discovery uses a low-privilege datagram ping socket with bounded in-flight
probes. Limited port scans use ordinary, rate-limited TCP connect sockets.
The opt-in security profile runs Nmap in its **own session/process group**
with fixed argv lists (never a shell, never operator-supplied flags). Stopping
a job -- cancel, timeout, lost lease or worker shutdown -- closes the socket or
signals the whole process group, so no scanner can outlive the job.

Targets are re-validated against the *current* authorized scope immediately
before running (the scope may have changed since the job was queued), and are
split into small chunks so progress is real and a stop request is honoured
between and during chunks.
"""
from __future__ import annotations

import dataclasses
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

from . import scan_policy
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
from .tcp_scanner import TcpConnectScanner, TcpDeadlineExceeded, TcpProbeState

logger = logging.getLogger("home_noc.scan_runner")

CHUNK_PREFIX = 27            # at most 32 addresses per scanner invocation
POLL_SECONDS = 0.25          # how often a running scanner is checked
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_RESULT_HOSTS = 1024
ICMP_PROGRESS_ADDRESS_INTERVAL = 32
ICMP_PROGRESS_TIME_INTERVAL = 1.0


class JobStopped(Exception):
    """The job must stop now. ``reason``: cancel | lost | shutdown | revoked.

    ``revoked`` means the *current* scan policy no longer authorizes the job
    (``detail`` is the denial code). ``partial`` optionally carries a result
    summary of legitimate observations gathered before the stop.
    """

    def __init__(self, reason: str, detail: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail
        self.partial: dict | None = None


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
    # Returns the *current* stored scan policy (raises PolicyUnavailable). The
    # worker wires this to its own database; None falls back to the default engine.
    policy_loader: Callable[[], scan_policy.PolicyState] | None = None


# Authorization is re-read at most this often while a job runs. Revocation takes
# effect at the next check after the policy revision changes, so at most this
# interval plus the probes already in flight (bounded by the profile's
# concurrency and per-probe timeout) can follow a revocation.
POLICY_RECHECK_SECONDS = 0.5


class _Authorizer:
    """Authorizes a job at start and keeps re-validating it while it runs."""

    def __init__(self, ctx: JobContext, profile: ScanProfile):
        self.ctx = ctx
        self.profile = profile
        self.loader = ctx.policy_loader or scan_policy.load_current_policy
        self.revision: int | None = None
        self._next_at = 0.0
        self._unavailable_since: float | None = None

    def authorize(self) -> list[ipaddress.IPv4Network]:
        """Initial check; raises ``RunnerError`` (non-retryable) on denial."""
        try:
            policy = self.loader()
            check_profile_enabled(self.profile)
            networks, _ = resolve_targets(self.ctx.targets, self.profile, policy)
        except scan_policy.PolicyUnavailable as exc:
            raise RunnerError("scope_rejected", exc.message, retryable=False) from None
        except ScopeError as exc:
            raise RunnerError("scope_rejected", exc.message, retryable=False) from None
        self.revision = policy.revision
        return networks

    def check(self) -> None:
        """Handed to scanners in place of ``ctx.check``: honours cancel/lease/
        shutdown first, then revocation. Called before every probe dispatch
        round, so no new probe is scheduled once a revocation is observed."""
        self.ctx.check()
        now = time.monotonic()
        if now < self._next_at:
            return
        self._next_at = now + POLICY_RECHECK_SECONDS
        try:
            policy = self.loader()
        except scan_policy.PolicyUnavailable as exc:
            if not exc.transient:
                raise JobStopped("revoked", exc.code) from None
            # A transient database error may not kill a job straight away, but
            # authorization that cannot be verified for a full lease is denied.
            self._unavailable_since = self._unavailable_since or now
            if now - self._unavailable_since >= settings.worker_lease_seconds:
                raise JobStopped("revoked", exc.code) from None
            return
        self._unavailable_since = None
        if policy.revision == self.revision:
            return
        try:
            check_profile_enabled(self.profile)
            resolve_targets(self.ctx.targets, self.profile, policy)
        except ScopeError as exc:
            raise JobStopped("revoked", exc.code) from None
        self.revision = policy.revision


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
    if spec.name != ScanProfile.SECURITY:
        raise ValueError(f"{spec.name.value} profile does not use nmap")
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
    # Authorization is re-checked at execution time, not only at enqueue, and
    # again continuously while running (see ``_Authorizer.check``).
    authorizer = _Authorizer(ctx, profile)
    networks = authorizer.authorize()
    ctx = dataclasses.replace(ctx, check=authorizer.check)

    spec = PROFILES[profile]
    if profile == ScanProfile.DISCOVERY:
        return _run_icmp_discovery(ctx, spec, networks)
    if profile == ScanProfile.PORTS:
        return _run_tcp_connect(ctx, spec, networks)

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


def _run_tcp_connect(
    ctx: JobContext, spec: ProfileSpec, networks: list[ipaddress.IPv4Network]
) -> dict:
    targets = expand_targets(networks)
    started = datetime.now(UTC)
    deadline = time.monotonic() + spec.timeout_seconds
    try:
        ports = settings.scan_tcp_ports
        scanner = TcpConnectScanner(
            ports=ports,
            max_ports=settings.scan_tcp_max_ports,
            max_concurrency=spec.max_concurrency,
            connections_per_second=settings.scan_tcp_connections_per_second,
            connection_timeout=settings.scan_tcp_connection_timeout_seconds,
            max_total_connections=settings.scan_tcp_max_total_connections,
        )
    except ValueError as exc:
        raise RunnerError(
            "invalid_scanner_config",
            f"TCP scanner configuration is invalid: {exc}",
            retryable=False,
        ) from None

    total = len(targets) * len(scanner.ports)
    ctx.event(
        "plan",
        f"TCP connect scan of {len(targets)} host(s) and {len(scanner.ports)} port(s); "
        f"at most {spec.max_concurrency} connection(s) in flight and "
        f"{settings.scan_tcp_connections_per_second:g} start(s)/second",
    )
    last_progress_at = time.monotonic()
    last_progress_done = 0

    def persist_progress(done: int, progress_total: int) -> None:
        nonlocal last_progress_at, last_progress_done
        now = time.monotonic()
        if (
            done == 0
            or done == progress_total
            or done - last_progress_done >= ICMP_PROGRESS_ADDRESS_INTERVAL
            or now - last_progress_at >= ICMP_PROGRESS_TIME_INTERVAL
        ):
            ctx.progress(done, progress_total)
            last_progress_at = now
            last_progress_done = done

    try:
        scan = scanner.scan(
            targets, deadline=deadline, check=ctx.check, progress=persist_progress
        )
    except JobStopped as stop:
        if stop.reason == "revoked":
            # Keep what was legitimately observed before authorization ended.
            done = getattr(stop, "partial_observations", ())
            stop.partial = _tcp_summary(
                list(done), list(scanner.ports), total, started, partial=True
            )
        raise
    except TcpDeadlineExceeded:
        raise RunnerError("timeout", "Scan exceeded its time limit", retryable=False) from None
    except ValueError as exc:
        raise RunnerError(
            "invalid_scanner_config",
            f"TCP scanner plan is invalid: {exc}",
            retryable=False,
        ) from None

    summary = _tcp_summary(
        list(scan.observations), list(scanner.ports), total, started, partial=False
    )
    state_counts = summary["state_counts"]
    ctx.event(
        "ports_done",
        f"TCP connect scan completed: {state_counts['open']} open, "
        f"{state_counts['refused']} refused, {state_counts['timeout']} timed out, "
        f"{state_counts['inconclusive']} inconclusive",
    )
    return summary


def _tcp_summary(
    items: list, ports: list[int], total: int, started: datetime, *, partial: bool,
) -> dict:
    finished = datetime.now(UTC)
    observations = [
        {
            "host": item.host,
            "port": item.port,
            "protocol": "tcp",
            "state": item.state.value,
            "observed_at": item.observed_at.isoformat(),
        }
        for item in items
    ]
    open_by_host: dict[str, list[int]] = {}
    state_counts = {state.value: 0 for state in TcpProbeState}
    for item in items:
        state_counts[item.state.value] += 1
        if item.state == TcpProbeState.OPEN:
            open_by_host.setdefault(item.host, []).append(item.port)
    hosts = [
        {"ip": host, "open_ports": sorted(open_by_host[host])}
        for host in sorted(open_by_host, key=ipaddress.IPv4Address)
    ]
    summary = {
        "profile": ScanProfile.PORTS.value,
        "probe": "tcp_connect",
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "ports": ports,
        "attempted": total,
        "state_counts": state_counts,
        # Positive TCP connections prove responsiveness. Missing entries are
        # deliberately not interpreted as offline hosts.
        "hosts_up": len(hosts),
        "hosts": hosts,
        "observations": observations,
        "truncated": False,
    }
    if partial:
        summary["partial"] = True
        summary["attempted"] = len(items)
    return summary


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
    last_progress_at = time.monotonic()
    last_progress_done = 0

    def persist_progress(done: int, total: int) -> None:
        """Bound SQLite writes while keeping long-running jobs observable."""
        nonlocal last_progress_at, last_progress_done
        now = time.monotonic()
        if (
            done == 0
            or done == total
            or done - last_progress_done >= ICMP_PROGRESS_ADDRESS_INTERVAL
            or now - last_progress_at >= ICMP_PROGRESS_TIME_INTERVAL
        ):
            ctx.progress(done, total)
            last_progress_at = now
            last_progress_done = done

    try:
        result = scanner.scan(
            targets, deadline=deadline, check=ctx.check, progress=persist_progress
        )
    except JobStopped as stop:
        if stop.reason == "revoked":
            responsive = getattr(stop, "partial_responsive", ())
            stop.partial = {
                "profile": ScanProfile.DISCOVERY.value,
                "probe": "icmp_echo",
                "started_at": started.isoformat(),
                "finished_at": datetime.now(UTC).isoformat(),
                "attempted": len(responsive),
                "hosts_up": len(responsive),
                "hosts": [
                    {"ip": h.ip, "responsive": True, "observed_at": h.observed_at.isoformat()}
                    for h in responsive[:MAX_RESULT_HOSTS]
                ],
                "unanswered": 0,
                "unanswered_status": "inconclusive",
                "truncated": len(responsive) > MAX_RESULT_HOSTS,
                "partial": True,
            }
        raise
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
