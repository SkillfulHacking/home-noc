"""M10 low-privilege ICMP scanner tests.

All network behavior is mocked except the explicitly isolated loopback test.
No test probes a LAN, public address, or external host.
"""
from __future__ import annotations

import socket
import time
from datetime import UTC, datetime

import pytest

from app.icmp_scanner import (
    IcmpDeadlineExceeded,
    IcmpScanner,
    IcmpUnavailable,
    LinuxPingSocket,
    expand_targets,
)


class FakeTransport:
    def __init__(self, responsive=()):
        self.responsive = set(responsive)
        self.sent: list[tuple[str, int]] = []
        self.returned: set[int] = set()
        self.closed = False
        self.first_receive_send_count: int | None = None

    def send(self, target, sequence):
        self.sent.append((target, sequence))
        return True

    def receive(self, timeout):
        if self.first_receive_send_count is None:
            self.first_receive_send_count = len(self.sent)
        for target, sequence in self.sent:
            if target in self.responsive and sequence not in self.returned:
                self.returned.add(sequence)
                return target, sequence
        time.sleep(max(timeout, 0))
        return None

    def close(self):
        self.closed = True


def scanner_with(transport, *, concurrency=2, timeout=0.01):
    observed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    return IcmpScanner(
        max_concurrency=concurrency,
        probe_timeout=timeout,
        poll_interval=0.002,
        transport_factory=lambda: transport,
        utcnow=lambda: observed,
    )


def test_expands_a_slash_24_and_individual_host_without_network_or_broadcast():
    import ipaddress

    targets = expand_targets([
        ipaddress.IPv4Network("192.0.2.0/24"),
        ipaddress.IPv4Network("198.51.100.7/32"),
    ])
    assert len(targets) == 255
    assert targets[:2] == ["192.0.2.1", "192.0.2.2"]
    assert "192.0.2.0" not in targets and "192.0.2.255" not in targets
    assert "198.51.100.7" in targets


def test_success_unanswered_partial_results_and_bounded_concurrency():
    transport = FakeTransport({"192.0.2.1", "192.0.2.3"})
    progress = []
    result = scanner_with(transport).scan(
        ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
        deadline=time.monotonic() + 1,
        progress=lambda done, total: progress.append((done, total)),
    )
    assert [host.ip for host in result.responsive] == ["192.0.2.1", "192.0.2.3"]
    assert all(host.observed_at.tzinfo is UTC for host in result.responsive)
    assert result.attempted == 4 and result.unanswered == 2
    assert transport.first_receive_send_count == 2  # never fills beyond the configured bound
    assert progress[0] == (0, 4) and progress[-1] == (4, 4)
    assert transport.closed


def test_all_unanswered_is_inconclusive_not_an_error():
    result = scanner_with(FakeTransport(), timeout=0.002).scan(
        ["192.0.2.10", "192.0.2.11"], deadline=time.monotonic() + 1
    )
    assert result.responsive == () and result.unanswered == 2


@pytest.mark.parametrize("target", ["hostname", "::1", "192.0.2.999", "-c1"])
def test_invalid_input_is_rejected_before_transport(target):
    opened = False

    def factory():
        nonlocal opened
        opened = True
        return FakeTransport()

    scanner = IcmpScanner(max_concurrency=1, probe_timeout=1, transport_factory=factory)
    with pytest.raises(ValueError, match="IPv4 literals"):
        scanner.scan([target], deadline=time.monotonic() + 1)
    assert not opened


def test_expired_deadline_closes_transport():
    transport = FakeTransport()
    with pytest.raises(IcmpDeadlineExceeded):
        scanner_with(transport).scan(["192.0.2.1"], deadline=time.monotonic() - 1)
    assert transport.closed


def test_cancellation_propagates_and_closes_transport():
    transport = FakeTransport()

    def cancel():
        raise RuntimeError("cancelled")

    with pytest.raises(RuntimeError, match="cancelled"):
        scanner_with(transport).scan(
            ["192.0.2.1"], deadline=time.monotonic() + 1, check=cancel
        )
    assert transport.closed


def test_permission_failure_is_distinct_from_unanswered():
    def denied():
        raise IcmpUnavailable("not permitted")

    scanner = IcmpScanner(max_concurrency=1, probe_timeout=1, transport_factory=denied)
    with pytest.raises(IcmpUnavailable, match="not permitted"):
        scanner.scan(["192.0.2.1"], deadline=time.monotonic() + 1)


def test_real_loopback_directly_exercises_isolated_scanner():
    """Production scope still forbids loopback; only this scanner unit uses it."""
    scanner = IcmpScanner(max_concurrency=1, probe_timeout=1)
    try:
        result = scanner.scan(["127.0.0.1"], deadline=time.monotonic() + 3)
    except IcmpUnavailable as exc:
        pytest.skip(f"host does not permit unprivileged ping sockets: {exc}")
    assert [host.ip for host in result.responsive] == ["127.0.0.1"]


def test_linux_transport_uses_datagram_not_raw_socket(monkeypatch):
    calls = []

    class Sock:
        def setblocking(self, value):
            assert value is False

        def close(self):
            pass

    def make_socket(family, type_, protocol):
        calls.append((family, type_, protocol))
        return Sock()

    monkeypatch.setattr("app.icmp_scanner.socket.socket", make_socket)
    transport = LinuxPingSocket()
    transport.close()
    assert calls == [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)]
