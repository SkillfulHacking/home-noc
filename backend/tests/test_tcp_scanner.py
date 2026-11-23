"""M11 TCP connect scanner: no external or LAN scanning."""
from __future__ import annotations

import errno
import socket
import threading
import time

import pytest

from app.tcp_scanner import (
    SocketConnector,
    TcpConnectScanner,
    TcpDeadlineExceeded,
    TcpProbeState,
    validate_ports,
)


def scanner(*, ports=(22,), connector=None, max_concurrency=2, rate=1000):
    return TcpConnectScanner(
        ports=ports,
        max_ports=20,
        max_concurrency=max_concurrency,
        connections_per_second=rate,
        connection_timeout=0.25,
        max_total_connections=20,
        connector=connector,
    )


def test_real_loopback_open_and_refused_connect():
    # Direct socket test; it deliberately does not alter authorization policy.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listening:
        listening.bind(("127.0.0.1", 0))
        listening.listen(1)
        port = listening.getsockname()[1]
        result = scanner(ports=(port,)).scan(
            ["127.0.0.1"], deadline=time.monotonic() + 2
        )
        assert result.attempted == 1
        assert result.observations[0].state == TcpProbeState.OPEN
        assert result.observations[0].observed_at.tzinfo is not None

    # Reserve a TCP port without listening. This prevents another process
    # from reusing it while we verify that connections are refused.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        closed_port = reserved.getsockname()[1]
        assert (
            SocketConnector().probe("127.0.0.1", closed_port, 0.25)
            == TcpProbeState.REFUSED
        )


@pytest.mark.parametrize("error_code", [
    errno.ETIMEDOUT,
    errno.EAGAIN,
    errno.EWOULDBLOCK,
])
def test_connect_ex_timeout_errno_is_classified_correctly(
    monkeypatch, error_code
):
    from app import tcp_scanner

    class FakeSocket:
        def __init__(self):
            self.closed = False
            self.timeout = None

        def settimeout(self, value):
            self.timeout = value

        def connect_ex(self, address):
            assert address == ("192.0.2.1", 443)
            return error_code

        def close(self):
            self.closed = True

    fake = FakeSocket()
    monkeypatch.setattr(
        tcp_scanner.socket, "socket", lambda *_args, **_kwargs: fake
    )

    assert SocketConnector().probe("192.0.2.1", 443, 0.25) == (
        TcpProbeState.TIMEOUT
    )
    assert fake.timeout == 0.25
    assert fake.closed


@pytest.mark.parametrize("ports", [(), (0,), (65536,), (22, 22), (True,), (22.5,)])
def test_invalid_port_sets_rejected_before_probing(ports):
    with pytest.raises(ValueError):
        validate_ports(ports, max_ports=20)


@pytest.mark.parametrize("targets", [["example.com"], ["not-an-ip"], ["::1"]])
def test_only_ipv4_literals_accepted(targets):
    with pytest.raises(ValueError):
        scanner().scan(targets, deadline=time.monotonic() + 2)


def test_mocked_responses_normalized_and_sorted():
    class Fake:
        def probe(self, host, port, timeout):
            assert timeout > 0
            if port == 80:
                return TcpProbeState.OPEN
            if port == 443:
                return TcpProbeState.REFUSED
            if port == 8080:
                return TcpProbeState.TIMEOUT
            return TcpProbeState.INCONCLUSIVE

    result = scanner(ports=(8080, 80, 443, 1234), connector=Fake()).scan(
        ["192.0.2.2", "192.0.2.1"], deadline=time.monotonic() + 3
    )
    assert result.attempted == 8
    assert [(o.host, o.port) for o in result.observations] == [
        (host, port) for host in ("192.0.2.1", "192.0.2.2")
        for port in (80, 443, 1234, 8080)
    ]
    assert {o.state for o in result.observations} == set(TcpProbeState)


def test_concurrent_connections_are_bounded():
    lock = threading.Lock()
    state = {"active": 0, "peak": 0}

    class Fake:
        def probe(self, host, port, timeout):
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            try:
                time.sleep(0.025)
                return TcpProbeState.REFUSED
            finally:
                with lock:
                    state["active"] -= 1

    results = scanner(
        ports=(20, 21, 22, 23, 24, 25), connector=Fake(), max_concurrency=2
    ).scan(["192.0.2.1"], deadline=time.monotonic() + 3)
    assert results.attempted == 6
    assert 1 <= state["peak"] <= 2
    assert state["active"] == 0


def test_connection_start_rate_is_limited():
    starts = []

    class Fake:
        def probe(self, host, port, timeout):
            starts.append(time.monotonic())
            return TcpProbeState.REFUSED

    scanner(ports=(20, 21, 22), connector=Fake(), rate=20).scan(
        ["192.0.2.1"], deadline=time.monotonic() + 2
    )
    assert len(starts) == 3
    assert starts[1] - starts[0] >= 0.03
    assert starts[2] - starts[1] >= 0.03


def test_overall_deadline_stops_scan():
    class Slow:
        def probe(self, host, port, timeout):
            time.sleep(0.1)
            return TcpProbeState.TIMEOUT

    with pytest.raises(TcpDeadlineExceeded):
        scanner(ports=(80, 81), connector=Slow(), max_concurrency=1).scan(
            ["192.0.2.1"], deadline=time.monotonic() + 0.02
        )


def test_cancellation_stops_scheduling_and_joins_threads():
    class Cancelled(Exception):
        pass

    started = []

    class Fake:
        def probe(self, host, port, timeout):
            started.append(port)
            time.sleep(0.01)
            return TcpProbeState.INCONCLUSIVE

    def cancel_on_progress(done, total):
        if done >= 1:
            raise Cancelled

    with pytest.raises(Cancelled):
        scanner(ports=(20, 21, 22, 23), connector=Fake()).scan(
            ["192.0.2.1"], deadline=time.monotonic() + 2,
            progress=cancel_on_progress,
        )
    assert 1 <= len(started) <= 2


def test_connection_work_limit_enforced_before_probing():
    class Never:
        def probe(self, host, port, timeout):
            pytest.fail("No socket should open when work cap is exceeded")

    limit = TcpConnectScanner(
        ports=(22, 80), max_ports=20, max_concurrency=2,
        connections_per_second=100, connection_timeout=0.2,
        max_total_connections=3, connector=Never(),
    )
    with pytest.raises(ValueError, match="limit"):
        limit.scan(["192.0.2.1", "192.0.2.2"], deadline=time.monotonic() + 2)
