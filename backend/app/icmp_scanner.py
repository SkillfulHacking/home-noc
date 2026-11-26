"""Low-privilege IPv4 ICMP echo discovery.

Linux ``SOCK_DGRAM`` ICMP sockets ("ping sockets") do not require
``CAP_NET_RAW`` when the process group is allowed by
``net.ipv4.ping_group_range``.  The Compose worker grants only its own GID
that permission; the API container gets neither the sysctl nor a capability.

The scanner is deliberately independent of jobs, SQLAlchemy and FastAPI.
Callers supply a deadline, cancellation check and progress callback, making
the scheduling and result semantics directly testable with a fake transport.
"""
from __future__ import annotations

import errno
import ipaddress
import select
import socket
import struct
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
_ICMP_HEADER = struct.Struct("!BBHHH")
_PAYLOAD = b"home-noc"
_PERMISSION_ERRORS = {errno.EACCES, errno.EPERM, errno.EPROTONOSUPPORT}


class IcmpUnavailable(RuntimeError):
    """The runtime cannot open or use a low-privilege ICMP ping socket."""


class IcmpDeadlineExceeded(TimeoutError):
    """The caller's overall execution deadline expired."""


@dataclass(frozen=True)
class ResponsiveHost:
    ip: str
    observed_at: datetime


@dataclass(frozen=True)
class IcmpScanResult:
    attempted: int
    responsive: tuple[ResponsiveHost, ...]

    @property
    def unanswered(self) -> int:
        return self.attempted - len(self.responsive)


class IcmpTransport(Protocol):
    def send(self, target: str, sequence: int) -> bool:
        """Send one echo request; false means it was locally inconclusive."""

    def receive(self, timeout: float) -> tuple[str, int] | None:
        """Return ``(source IPv4, sequence)`` or ``None`` on timeout."""

    def close(self) -> None: ...


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _echo_packet(sequence: int) -> bytes:
    header = _ICMP_HEADER.pack(ICMP_ECHO_REQUEST, 0, 0, 0, sequence)
    checksum = _checksum(header + _PAYLOAD)
    return _ICMP_HEADER.pack(ICMP_ECHO_REQUEST, 0, checksum, 0, sequence) + _PAYLOAD


class LinuxPingSocket:
    """One Linux datagram ICMP socket; safe for IPv4 literals only."""

    def __init__(self) -> None:
        ping_socket: socket.socket | None = None
        try:
            ping_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            ping_socket.setblocking(False)
        except OSError as exc:
            if ping_socket is not None:
                ping_socket.close()
            if exc.errno in _PERMISSION_ERRORS:
                raise IcmpUnavailable("ICMP ping sockets are not permitted") from None
            raise IcmpUnavailable("ICMP ping sockets are unavailable") from None
        self._socket = ping_socket

    def send(self, target: str, sequence: int) -> bool:
        try:
            self._socket.sendto(_echo_packet(sequence), (target, 0))
        except OSError as exc:
            if exc.errno in _PERMISSION_ERRORS:
                raise IcmpUnavailable("ICMP ping sockets are not permitted") from None
            # No route, unreachable interface, and other target-specific send
            # errors are inconclusive observations, not scanner failures.
            return False
        return True

    def receive(self, timeout: float) -> tuple[str, int] | None:
        readable, _, _ = select.select([self._socket], [], [], max(timeout, 0.0))
        if not readable:
            return None
        try:
            packet, peer = self._socket.recvfrom(4096)
        except BlockingIOError:
            return None
        if len(packet) < _ICMP_HEADER.size:
            return None
        type_, code, _checksum_value, _identifier, sequence = _ICMP_HEADER.unpack_from(packet)
        if type_ != ICMP_ECHO_REPLY or code != 0:
            return None
        try:
            source = str(ipaddress.IPv4Address(peer[0]))
        except ipaddress.AddressValueError:
            return None
        return source, sequence

    def close(self) -> None:
        self._socket.close()


def expand_targets(networks: Iterable[ipaddress.IPv4Network]) -> list[str]:
    """Expand validated networks without probing network/broadcast addresses."""
    addresses: set[ipaddress.IPv4Address] = set()
    for network in networks:
        addresses.update(network.hosts())
    return [str(address) for address in sorted(addresses)]


class IcmpScanner:
    """Bounded ICMP scheduler with explicit per-probe and overall deadlines."""

    def __init__(
        self,
        *,
        max_concurrency: int,
        probe_timeout: float,
        poll_interval: float = 0.25,
        transport_factory: Callable[[], IcmpTransport] = LinuxPingSocket,
        monotonic: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        if probe_timeout <= 0 or poll_interval <= 0:
            raise ValueError("timeouts must be positive")
        self.max_concurrency = max_concurrency
        self.probe_timeout = probe_timeout
        self.poll_interval = poll_interval
        self.transport_factory = transport_factory
        self.monotonic = monotonic
        self.utcnow = utcnow

    def scan(
        self,
        targets: Iterable[str],
        *,
        deadline: float,
        check: Callable[[], None] = lambda: None,
        progress: Callable[[int, int], None] = lambda _done, _total: None,
    ) -> IcmpScanResult:
        pending = deque(_validated_targets(targets))
        total = len(pending)
        progress(0, total)
        if not pending:
            return IcmpScanResult(attempted=0, responsive=())

        transport = self.transport_factory()
        outstanding: dict[int, tuple[str, float]] = {}
        responsive: dict[str, ResponsiveHost] = {}
        completed = 0
        sequence = 1
        try:
            while pending or outstanding:
                check()
                now = self.monotonic()
                if now >= deadline:
                    raise IcmpDeadlineExceeded

                while pending and len(outstanding) < self.max_concurrency:
                    check()  # re-authorize/stop before *every* probe, not per batch
                    target = pending.popleft()
                    current_sequence = sequence
                    sequence = 1 if sequence == 65_535 else sequence + 1
                    if transport.send(target, current_sequence):
                        outstanding[current_sequence] = (target, self.monotonic())
                    else:
                        completed += 1
                        progress(completed, total)

                now = self.monotonic()
                expired = [
                    seq for seq, (_target, sent_at) in outstanding.items()
                    if now - sent_at >= self.probe_timeout
                ]
                for seq in expired:
                    outstanding.pop(seq)
                    completed += 1
                    progress(completed, total)
                if not outstanding:
                    continue

                earliest_expiry = min(sent + self.probe_timeout for _, sent in outstanding.values())
                wait = min(self.poll_interval, earliest_expiry - now, deadline - now)
                reply = transport.receive(max(wait, 0.0))
                if reply is None:
                    continue
                source, reply_sequence = reply
                expected = outstanding.get(reply_sequence)
                if expected is None or expected[0] != source:
                    continue
                outstanding.pop(reply_sequence)
                responsive[source] = ResponsiveHost(source, self.utcnow())
                completed += 1
                progress(completed, total)
        except BaseException as exc:
            # Keep replies already received so a stop does not discard them.
            exc.partial_responsive = tuple(  # type: ignore[attr-defined]
                responsive[ip] for ip in sorted(responsive, key=ipaddress.IPv4Address)
            )
            raise
        finally:
            transport.close()

        ordered = tuple(responsive[ip] for ip in sorted(responsive, key=ipaddress.IPv4Address))
        return IcmpScanResult(attempted=total, responsive=ordered)


def _validated_targets(targets: Iterable[str]) -> list[str]:
    normalized: set[ipaddress.IPv4Address] = set()
    for target in targets:
        try:
            normalized.add(ipaddress.IPv4Address(target))
        except ipaddress.AddressValueError:
            raise ValueError("ICMP targets must be IPv4 literals") from None
    return [str(address) for address in sorted(normalized)]
