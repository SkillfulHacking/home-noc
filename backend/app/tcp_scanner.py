"""Bounded, unprivileged IPv4 TCP connect scanning.

The scanner has no knowledge of jobs, databases, or authorization policy.
Callers provide already-authorized IPv4 literals, an overall deadline, and
callbacks for cancellation and progress.  Network behavior is injected via
``TcpConnector`` so scheduling and classification are testable without
sending packets.
"""
from __future__ import annotations

import errno
import ipaddress
import socket
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

MIN_PORT = 1
MAX_PORT = 65_535
POLL_SECONDS = 0.1


class TcpDeadlineExceeded(TimeoutError):
    """The overall scan deadline expired."""


class TcpProbeState(StrEnum):
    OPEN = "open"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class TcpObservation:
    host: str
    port: int
    state: TcpProbeState
    observed_at: datetime


@dataclass(frozen=True)
class TcpScanResult:
    observations: tuple[TcpObservation, ...]

    @property
    def attempted(self) -> int:
        return len(self.observations)


class TcpConnector(Protocol):
    def probe(self, host: str, port: int, timeout: float) -> TcpProbeState: ...


class SocketConnector:
    """Ordinary TCP sockets only; no raw socket, subprocess, or DNS lookup."""

    def probe(self, host: str, port: int, timeout: float) -> TcpProbeState:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
        except TimeoutError:
            return TcpProbeState.TIMEOUT
        except OSError as exc:
            code = exc.errno
        finally:
            sock.close()

        if code == 0:
            return TcpProbeState.OPEN
        if code == errno.ECONNREFUSED:
            return TcpProbeState.REFUSED
        # connect_ex may return EAGAIN/EWOULDBLOCK when the
        # configured socket timeout expires on Linux.
        if code in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
            return TcpProbeState.TIMEOUT
        return TcpProbeState.INCONCLUSIVE


def validate_ports(ports: Iterable[int], *, max_ports: int) -> tuple[int, ...]:
    if max_ports < 1:
        raise ValueError("max_ports must be positive")
    normalized = tuple(ports)
    if not normalized:
        raise ValueError("at least one TCP port is required")
    if len(normalized) > max_ports:
        raise ValueError(f"at most {max_ports} TCP ports are allowed")
    if any(isinstance(port, bool) or not isinstance(port, int) for port in normalized):
        raise ValueError("TCP ports must be integers")
    if any(port < MIN_PORT or port > MAX_PORT for port in normalized):
        raise ValueError("TCP ports must be between 1 and 65535")
    if len(set(normalized)) != len(normalized):
        raise ValueError("duplicate TCP ports are not allowed")
    return tuple(sorted(normalized))


def _validate_targets(targets: Iterable[str]) -> tuple[str, ...]:
    addresses: set[ipaddress.IPv4Address] = set()
    for target in targets:
        try:
            addresses.add(ipaddress.IPv4Address(target))
        except ipaddress.AddressValueError:
            raise ValueError("TCP targets must be IPv4 literals") from None
    return tuple(str(address) for address in sorted(addresses))


class TcpConnectScanner:
    """Rate-limited scheduler whose executor bounds actual socket calls."""

    def __init__(
        self,
        *,
        ports: Sequence[int],
        max_ports: int,
        max_concurrency: int,
        connections_per_second: float,
        connection_timeout: float,
        max_total_connections: int,
        connector: TcpConnector | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.ports = validate_ports(ports, max_ports=max_ports)
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        if connections_per_second <= 0:
            raise ValueError("connections_per_second must be positive")
        if connection_timeout <= 0:
            raise ValueError("connection_timeout must be positive")
        if max_total_connections < 1:
            raise ValueError("max_total_connections must be positive")
        self.max_concurrency = max_concurrency
        self.connections_per_second = connections_per_second
        self.connection_timeout = connection_timeout
        self.max_total_connections = max_total_connections
        self.connector = connector or SocketConnector()
        self.monotonic = monotonic
        self.sleep = sleep
        self.utcnow = utcnow

    def scan(
        self,
        targets: Iterable[str],
        *,
        deadline: float,
        check: Callable[[], None] = lambda: None,
        progress: Callable[[int, int], None] = lambda _done, _total: None,
    ) -> TcpScanResult:
        hosts = _validate_targets(targets)
        probes = [(host, port) for host in hosts for port in self.ports]
        total = len(probes)
        if total > self.max_total_connections:
            raise ValueError(
                f"scan requires {total} connections; limit is {self.max_total_connections}"
            )
        progress(0, total)
        if not probes:
            return TcpScanResult(())

        observations: list[TcpObservation] = []
        pending: dict[Future[TcpProbeState], tuple[str, int]] = {}
        next_probe_at = self.monotonic()
        completed = 0
        executor = ThreadPoolExecutor(
            max_workers=self.max_concurrency, thread_name_prefix="tcp-connect"
        )
        try:
            while probes or pending:
                check()
                now = self.monotonic()
                if now >= deadline:
                    raise TcpDeadlineExceeded

                while probes and len(pending) < self.max_concurrency:
                    check()
                    now = self.monotonic()
                    if now < next_probe_at:
                        self._interruptible_sleep(next_probe_at - now, deadline, check)
                        continue
                    remaining = deadline - now
                    if remaining <= 0:
                        raise TcpDeadlineExceeded
                    host, port = probes.pop(0)
                    timeout = min(self.connection_timeout, remaining)
                    future = executor.submit(self.connector.probe, host, port, timeout)
                    pending[future] = (host, port)
                    next_probe_at = now + (1.0 / self.connections_per_second)

                if not pending:
                    continue
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise TcpDeadlineExceeded
                done, _ = wait(
                    pending,
                    timeout=min(POLL_SECONDS, remaining),
                    return_when=FIRST_COMPLETED,
                )
                for future in done:
                    host, port = pending.pop(future)
                    try:
                        state = future.result()
                    except Exception:  # connector failures are target-specific
                        state = TcpProbeState.INCONCLUSIVE
                    observations.append(TcpObservation(host, port, state, self.utcnow()))
                    completed += 1
                    progress(completed, total)
        except BaseException as exc:
            # A stop (cancel, revocation, deadline) must not discard the probes
            # that already finished; the caller may preserve them.
            exc.partial_observations = tuple(observations)  # type: ignore[attr-defined]
            raise
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

        observations.sort(key=lambda item: (ipaddress.IPv4Address(item.host), item.port))
        return TcpScanResult(tuple(observations))

    def _interruptible_sleep(
        self, duration: float, deadline: float, check: Callable[[], None]
    ) -> None:
        end = min(self.monotonic() + duration, deadline)
        while self.monotonic() < end:
            check()
            self.sleep(min(POLL_SECONDS, end - self.monotonic()))
        if self.monotonic() >= deadline:
            raise TcpDeadlineExceeded
