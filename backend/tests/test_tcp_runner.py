"""M11 worker-runner integration with fake TCP connectors; no network traffic."""
from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from app import scan_runner
from app.config import settings
from app.scan_runner import JobContext, RunnerError
from app.tcp_scanner import TcpObservation, TcpProbeState, TcpScanResult

pytestmark = pytest.mark.usefixtures("job_env")


def context(targets=("10.77.0.5",)):
    progress_calls = []
    events = []
    ctx = JobContext(
        job_id="fake-job", profile="ports", targets=list(targets), attempt=1,
        check=lambda: None,
        progress=lambda done, total: progress_calls.append((done, total)),
        event=lambda kind, message: events.append((kind, message)),
        set_pid=lambda _pid: pytest.fail("TCP scanner must not spawn subprocesses"),
    )
    return ctx, progress_calls, events


def test_ports_profile_routes_to_low_privilege_scanner(monkeypatch):
    monkeypatch.setattr(settings, "scan_tcp_ports_raw", "443")
    observed = datetime(2026, 1, 2, tzinfo=UTC)

    class FakeTcpScanner:
        def __init__(self, **kwargs):
            assert kwargs["ports"] == [443]
            assert kwargs["max_concurrency"] == 8
            self.ports = tuple(kwargs["ports"])

        def scan(self, targets, *, deadline, check, progress):
            assert targets == ["10.77.0.5"]
            assert deadline > time.monotonic()
            check()
            progress(0, 1)
            progress(1, 1)
            return TcpScanResult((
                TcpObservation("10.77.0.5", 443, TcpProbeState.OPEN, observed),
            ))

    monkeypatch.setattr(scan_runner, "TcpConnectScanner", FakeTcpScanner)
    ctx, calls, events = context()
    result = scan_runner.run_scan(ctx)
    assert result["probe"] == "tcp_connect"
    assert result["hosts"] == [{"ip": "10.77.0.5", "open_ports": [443]}]
    assert result["state_counts"]["open"] == 1
    assert result["observations"][0]["observed_at"] == observed.isoformat()
    assert calls == [(0, 1), (1, 1)]
    assert events[0][0] == "plan"
    assert events[-1][0] == "ports_done"


def test_revalidated_scope_stops_ports_before_opening_socket(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "10.88.0.0/24")

    class NeverTcpScanner:
        def __init__(self, **kwargs):
            pytest.fail("Out-of-scope job must not instantiate TCP scanner")

    monkeypatch.setattr(scan_runner, "TcpConnectScanner", NeverTcpScanner)
    ctx, _, _ = context()
    with pytest.raises(RunnerError) as error:
        scan_runner.run_scan(ctx)
    assert error.value.code == "scope_rejected"


def test_bad_tcp_port_configuration_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "scan_tcp_ports_raw", "[true, 443]")
    ctx, _, _ = context()
    with pytest.raises(RunnerError) as error:
        scan_runner.run_scan(ctx)
    assert error.value.code == "invalid_scanner_config"


@pytest.mark.parametrize("raw", ['[22.5]', '[true]', '[null]', '["22", 443.2]'])
def test_invalid_config_types_are_rejected(monkeypatch, raw):
    monkeypatch.setattr(settings, "scan_tcp_ports_raw", raw)
    with pytest.raises(ValueError, match="non-integer"):
        _ = settings.scan_tcp_ports
