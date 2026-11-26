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


# ------------------------------------------------ M08A revocation (worker)
# All fake connectors: nothing here opens a socket.

def _load(factory, job_id):
    from app.models import ScanJob

    with factory() as db:
        job = db.get(ScanJob, job_id)
        db.expunge(job)
        return job


def _enqueue(factory, profile="ports", targets=("10.77.0.5/32",), total=2):
    from app import jobs

    with factory() as db:
        return jobs.enqueue_scan(
            db, profile=profile, targets=list(targets), progress_total=total, created_by="t"
        ).id


def _revoke(factory):
    from conftest import set_policy

    with factory() as db:
        set_policy(db, private_enabled=False)


def _ordered_scanner(monkeypatch, dispatched, after_dispatch):
    """A scanner that follows the contract real scanners follow -- ``check()``
    immediately before every dispatch -- with a hook that runs right after a
    dispatch. No threads, sleeps or timers: the interleaving is fixed by code."""
    from datetime import UTC, datetime

    class OrderedScanner:
        def __init__(self, **_kw):
            self.ports = (80, 443, 8080)

        def scan(self, targets, *, deadline, check, progress):
            done = []
            for port in self.ports:
                try:
                    check()
                except BaseException as exc:
                    exc.partial_observations = tuple(done)
                    raise
                dispatched.append(port)
                done.append(
                    TcpObservation("10.77.0.5", port, TcpProbeState.OPEN, datetime.now(UTC))
                )
                after_dispatch(port)
            return TcpScanResult(tuple(done))

    monkeypatch.setattr(scan_runner, "TcpConnectScanner", OrderedScanner)


def test_revocation_committed_after_a_dispatch_blocks_every_later_dispatch(
    job_session_factory, monkeypatch
):
    from app.worker import Worker

    dispatched = []
    _ordered_scanner(
        monkeypatch, dispatched,
        lambda port: _revoke(job_session_factory) if port == 80 else None,
    )
    job_id = _enqueue(job_session_factory)
    assert Worker(job_session_factory, "w1").run_next() == job_id
    job = _load(job_session_factory, job_id)
    assert dispatched == [80]          # exactly the probe dispatched before the commit
    assert (job.status, job.error_code) == ("failed", "authorization_revoked")
    assert job.lease_owner is None and job.runner_pid is None   # no orphaned lease
    assert job.result["partial"] is True
    assert [o["port"] for o in job.result["observations"]] == [80]   # observation kept


def test_policy_store_outage_after_start_dispatches_nothing_further(
    job_session_factory, monkeypatch
):
    from app import scan_policy
    from app.worker import Worker

    real_load = scan_policy.load_policy
    calls = {"n": 0}

    def flaky_load(db):
        calls["n"] += 1
        if calls["n"] > 2:  # call 1 authorizes the job, call 2 the first dispatch
            raise scan_policy.PolicyUnavailable("policy_unavailable", "down", transient=True)
        return real_load(db)

    dispatched = []
    _ordered_scanner(monkeypatch, dispatched, lambda _port: None)
    monkeypatch.setattr(scan_policy, "load_policy", flaky_load)
    job_id = _enqueue(job_session_factory)
    Worker(job_session_factory, "w1").run_next()
    job = _load(job_session_factory, job_id)
    assert dispatched == [80]      # a *transient* outage still stops all further dispatch
    assert (job.status, job.error_code) == ("failed", "authorization_unverified")
    assert job.attempts == 1       # not retried into a silent re-run


def test_icmp_revocation_between_two_sends_stops_the_third(job_session_factory, monkeypatch):
    from app.icmp_scanner import IcmpScanner
    from app.worker import Worker

    sent = []

    class Transport:
        def send(self, target, seq):
            sent.append(target)
            if len(sent) == 2:
                _revoke(job_session_factory)   # commit lands while probe 2 is being sent
            return True

        def receive(self, timeout):
            return None

        def close(self):
            pass

    real = IcmpScanner
    monkeypatch.setattr(
        scan_runner, "IcmpScanner", lambda **kw: real(transport_factory=Transport, **kw)
    )
    job_id = _enqueue(job_session_factory, profile="discovery", targets=("10.77.0.0/28",))
    Worker(job_session_factory, "w1").run_next()
    job = _load(job_session_factory, job_id)
    assert len(sent) == 2                      # the third send never happened
    assert (job.status, job.error_code) == ("failed", "authorization_revoked")
    assert job.result["partial"] is True


def test_partial_result_persistence_failure_still_records_terminal_outcome(
    job_session_factory,
):
    from app.scan_runner import JobStopped
    from app.worker import Worker

    partial = {"profile": "ports", "probe": "tcp_connect", "partial": True, "hosts": []}

    def revoked(_ctx):
        stop = JobStopped("revoked", "private_scanning_disabled")
        stop.partial = partial
        raise stop

    def broken_persister(_db, _job_id, _result):
        raise RuntimeError("reconciliation exploded")

    job_id = _enqueue(job_session_factory)
    Worker(
        job_session_factory, "w1", executor=revoked, result_persister=broken_persister
    ).run_next()
    job = _load(job_session_factory, job_id)
    # Not left running for lease recovery: a meaningful terminal state with evidence.
    assert (job.status, job.error_code) == ("failed", "authorization_revoked")
    assert job.lease_owner is None and job.result["partial"] is True


def test_icmp_scanner_rechecks_authorization_before_every_probe():
    from app.icmp_scanner import IcmpScanner

    sent, checks = [], []

    class Transport:
        def send(self, target, seq):
            sent.append(target)
            return True

        def receive(self, timeout):
            return None

        def close(self):
            pass

    class Revoked(Exception):
        pass

    def check():
        checks.append(len(sent))
        if len(sent) >= 3:
            raise Revoked

    scanner = IcmpScanner(max_concurrency=16, probe_timeout=1.0, transport_factory=Transport)
    with pytest.raises(Revoked):
        scanner.scan([f"10.77.0.{i}" for i in range(1, 11)], deadline=time.monotonic() + 30,
                     check=check)
    assert len(sent) == 3  # not a whole batch of 16 dispatched after the stop


def test_queued_job_revoked_before_start_never_reaches_a_scanner(
    job_session_factory, monkeypatch
):
    from app.worker import Worker

    class Never:
        def __init__(self, **_kw):
            pytest.fail("revoked job must not start a scanner")

    monkeypatch.setattr(scan_runner, "TcpConnectScanner", Never)
    job_id = _enqueue(job_session_factory)
    _revoke(job_session_factory)
    Worker(job_session_factory, "w1").run_next()
    job = _load(job_session_factory, job_id)
    assert (job.status, job.error_code, job.attempts) == ("failed", "scope_rejected", 1)


def test_retried_job_is_revalidated_against_current_policy(job_session_factory, monkeypatch):
    from app.worker import Worker

    def flaky(_ctx):
        raise RunnerError("scanner_failed", "boom", retryable=True)

    job_id = _enqueue(job_session_factory)
    Worker(job_session_factory, "w1", executor=flaky).run_next()
    assert _load(job_session_factory, job_id).status == "queued"
    _revoke(job_session_factory)
    monkeypatch.setattr(
        scan_runner, "TcpConnectScanner",
        lambda **_kw: pytest.fail("retry must be re-authorized first"),
    )
    Worker(job_session_factory, "w1").run_next()
    job = _load(job_session_factory, job_id)
    assert (job.status, job.error_code, job.attempts) == ("failed", "scope_rejected", 2)


def test_recovered_job_is_revalidated_against_current_policy(
    job_session_factory, monkeypatch
):
    from datetime import UTC, datetime, timedelta

    from app import jobs
    from app.worker import Worker

    job_id = _enqueue(job_session_factory)
    with job_session_factory() as db:
        assert jobs.claim_next(db, "dead-worker").id == job_id
        from app.models import ScanJob

        db.query(ScanJob).update(
            {"lease_expires_at": datetime.now(UTC) - timedelta(seconds=60)}
        )
        db.commit()
        assert jobs.recover(db) == [(job_id, "requeued")]
    _revoke(job_session_factory)
    monkeypatch.setattr(
        scan_runner, "TcpConnectScanner",
        lambda **_kw: pytest.fail("recovered job must be re-authorized first"),
    )
    Worker(job_session_factory, "w2").run_next()
    assert _load(job_session_factory, job_id).error_code == "scope_rejected"


def test_unreadable_policy_denies_start_and_stops_running_jobs():
    from app import scan_policy
    from app.scan_runner import JobStopped, _Authorizer
    from app.scan_scope import ScanProfile

    def down(transient):
        def loader():
            raise scan_policy.PolicyUnavailable("policy_unavailable", "down", transient=transient)
        return loader

    ctx, _, _ = context()
    ctx.policy_loader = down(True)
    with pytest.raises(RunnerError) as err:
        scan_runner.run_scan(ctx)                       # cannot verify -> never starts
    assert err.value.code == "scope_rejected" and not err.value.retryable

    # Both an invalid/missing policy and a transient outage stop at the very first
    # check -- there is no grace period during which probes may still be dispatched.
    for transient in (False, True):
        auth = _Authorizer(ctx, ScanProfile.PORTS)
        auth.loader = down(transient)
        with pytest.raises(JobStopped) as stop:
            auth.check()
        assert stop.value.reason == "revoked" and stop.value.detail == "policy_unavailable"
