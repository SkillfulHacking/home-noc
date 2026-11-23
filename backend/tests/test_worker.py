"""Worker + scanner process control (M09).

A fake scanner script stands in for nmap, so no packet ever leaves the test
process. Process-group behaviour is verified against real child processes.
"""
from __future__ import annotations

import dataclasses
import os
import signal
import subprocess
import threading
import time
from datetime import UTC, datetime

import pytest

from app import jobs, scan_runner
from app.icmp_scanner import IcmpScanResult, IcmpUnavailable, ResponsiveHost
from app.models import ScanJob
from app.scan_runner import parse_grepable, plan_chunks
from app.scan_scope import PROFILES, ScanProfile
from app.worker import Worker

pytestmark = pytest.mark.usefixtures("job_env")

def test_heartbeat_uses_private_runtime_path(tmp_path, monkeypatch):
    from pathlib import Path

    from app import worker as worker_module

    assert worker_module.HEARTBEAT_FILE == Path(
        "/run/home-noc/worker-heartbeat"
    )

    heartbeat = tmp_path / "worker-heartbeat"
    monkeypatch.setattr(worker_module, "HEARTBEAT_FILE", heartbeat)
    Worker._touch_heartbeat()
    assert heartbeat.is_file()



@pytest.fixture
def nmap_enabled(job_env, monkeypatch):
    monkeypatch.setattr(job_env, "scan_security_profile_enabled", True)


GREPABLE_SCRIPT = """#!/bin/sh
for last; do :; done
printf 'Host: %s ()\\tStatus: Up\\n' "${last%/*}"
"""
# Leaves a long-lived grandchild so we can prove the whole group is killed.
SLEEPER_SCRIPT = """#!/bin/sh
sleep 300 &
echo $! > "PIDFILE"
wait
"""


@pytest.fixture
def make_scanner(tmp_path, monkeypatch, job_env):
    def make(body: str):
        script = tmp_path / "fake-nmap"
        script.write_text(body.replace("PIDFILE", str(tmp_path / "child.pid"))
                          .replace("MARKER", str(tmp_path / "ran")))
        script.chmod(0o755)
        monkeypatch.setattr(job_env, "scan_nmap_binary", str(script))
        return script
    return make


def enqueue(factory, targets=("10.77.0.0/28",), total=16, profile="ports"):
    with factory() as db:
        return jobs.enqueue_scan(
            db, profile=profile, targets=list(targets), progress_total=total,
            created_by="tester",
        ).id


def enqueue_nmap(factory, targets=("10.77.0.0/28",), total=16):
    return enqueue(factory, targets=targets, total=total, profile="security")


def load(factory, job_id) -> ScanJob:
    with factory() as db:
        job = db.get(ScanJob, job_id)
        db.expunge(job)
        return job


def wait_for(predicate, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def read_pid(path) -> int | None:
    try:
        text = path.read_text().strip()
    except FileNotFoundError:
        return None
    return int(text) if text else None


def alive(pid: int) -> bool:
    try:
        stat = open(f"/proc/{pid}/stat").read()  # noqa: SIM115
    except FileNotFoundError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"  # a zombie is already dead


# ------------------------------------------------------------- parsing

def test_parse_grepable_hosts_and_open_ports():
    text = (
        "# Nmap 7.x scan\n"
        "Host: 10.77.0.5 ()\tStatus: Up\n"
        "Host: 10.77.0.6 ()\tPorts: 22/open/tcp//ssh///, 80/closed/tcp//http///, "
        "443/open/tcp//https///\tIgnored State: filtered (18)\n"
        "Host: not-an-ip ()\tStatus: Up\n"
        "Host: 10.77.0.7 ()\tStatus: Down\n"
    )
    assert parse_grepable(text) == {"10.77.0.5": [], "10.77.0.6": [22, 443]}


def test_chunks_cover_the_range_exactly():
    import ipaddress

    chunks = plan_chunks([ipaddress.IPv4Network("10.77.0.0/24"),
                          ipaddress.IPv4Network("10.77.1.9/32")])
    assert len(chunks) == 9 and all(c.prefixlen >= scan_runner.CHUNK_PREFIX for c in chunks)
    assert sum(c.num_addresses for c in chunks) == 257


def test_argv_is_fixed_and_target_is_after_double_dash(job_env):
    import ipaddress

    with pytest.raises(ValueError, match="does not use nmap"):
        scan_runner.build_argv(
            PROFILES[ScanProfile.DISCOVERY], ipaddress.IPv4Network("10.77.0.0/28")
        )

    with pytest.raises(ValueError, match="does not use nmap"):
        scan_runner.build_argv(
            PROFILES[ScanProfile.PORTS],
            ipaddress.IPv4Network("10.77.0.0/28"),
        )

    # The opt-in security profile still enforces Nmap parallelism.
    for profile in (ScanProfile.SECURITY,):
        spec = PROFILES[profile]
        args = scan_runner.build_argv(
            spec, ipaddress.IPv4Network("10.77.0.0/28")
        )
        index = args.index("--max-parallelism")
        assert args[index + 1] == str(spec.max_concurrency)


# ------------------------------------------------------------ execution

@pytest.mark.usefixtures("nmap_enabled")
def test_successful_nmap_scan_records_progress_result_and_events(job_session_factory, make_scanner):
    make_scanner(GREPABLE_SCRIPT)
    job_id = enqueue_nmap(job_session_factory, ("10.77.0.0/28", "10.77.0.64/28"), total=32)
    assert Worker(job_session_factory, "w1").run_next() == job_id
    job = load(job_session_factory, job_id)
    assert job.status == "succeeded"
    assert (job.progress_done, job.progress_total) == (32, 32)
    assert job.result["hosts_up"] == 2
    assert job.result["hosts"][0] == {"ip": "10.77.0.0", "open_ports": []}
    assert job.runner_pid is None and job.lease_owner is None
    with job_session_factory() as db:
        types = [e.type for e in jobs.list_events(db, job_id)]
    assert types == ["queued", "started", "plan", "chunk_done", "chunk_done", "succeeded"]


def test_icmp_discovery_persists_structured_results(
    job_session_factory, monkeypatch
):
    observed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

    class FakeIcmpScanner:
        def __init__(self, **kwargs):
            assert kwargs["max_concurrency"] == 16

        def scan(self, targets, *, deadline, check, progress):
            assert targets == [f"10.77.0.{i}" for i in range(1, 15)]
            assert deadline > time.monotonic()
            check()
            progress(0, len(targets))
            progress(len(targets), len(targets))
            return IcmpScanResult(
                attempted=len(targets),
                responsive=(ResponsiveHost("10.77.0.5", observed),),
            )

    monkeypatch.setattr(scan_runner, "IcmpScanner", FakeIcmpScanner)
    job_id = enqueue(
        job_session_factory, targets=("10.77.0.0/28",), total=14, profile="discovery"
    )
    Worker(job_session_factory, "w1").run_next()
    job = load(job_session_factory, job_id)
    assert job.status == "succeeded"
    assert job.result["probe"] == "icmp_echo"
    assert job.result["hosts"] == [{
        "ip": "10.77.0.5", "responsive": True, "observed_at": observed.isoformat()
    }]
    assert job.result["hosts_up"] == 1
    assert job.result["unanswered"] == 13
    assert job.result["unanswered_status"] == "inconclusive"


def test_icmp_permission_failure_is_explicit_and_not_retried(
    job_session_factory, monkeypatch
):
    class DeniedScanner:
        def __init__(self, **_kwargs):
            pass

        def scan(self, *_args, **_kwargs):
            raise IcmpUnavailable

    monkeypatch.setattr(scan_runner, "IcmpScanner", DeniedScanner)
    job_id = enqueue(job_session_factory, total=14, profile="discovery")
    Worker(job_session_factory, "w1").run_next()
    job = load(job_session_factory, job_id)
    assert (job.status, job.error_code, job.attempts) == (
        "failed", "icmp_unavailable", 1
    )


def test_icmp_progress_persistence_is_throttled(monkeypatch, job_env):
    class ChattyScanner:
        def __init__(self, **_kwargs):
            pass

        def scan(self, targets, *, deadline, check, progress):
            progress(0, len(targets))
            for done in range(1, len(targets) + 1):
                progress(done, len(targets))
            return IcmpScanResult(attempted=len(targets), responsive=())

    monkeypatch.setattr(scan_runner, "IcmpScanner", ChattyScanner)
    writes = []
    ctx = scan_runner.JobContext(
        job_id="test",
        profile="discovery",
        targets=["10.77.0.0/24"],
        attempt=1,
        check=lambda: None,
        progress=lambda done, total: writes.append((done, total)),
        event=lambda _type, _message: None,
        set_pid=lambda _pid: None,
    )
    result = scan_runner.run_scan(ctx)
    assert result["attempted"] == 254
    assert writes == [
        (0, 254), (32, 254), (64, 254), (96, 254), (128, 254),
        (160, 254), (192, 254), (224, 254), (254, 254),
    ]


@pytest.mark.usefixtures("nmap_enabled")
def test_scanner_failure_retries_then_fails_with_bounded_attempts(
    job_session_factory, make_scanner, job_env, monkeypatch
):
    monkeypatch.setattr(job_env, "scan_job_max_attempts", 2)
    make_scanner("#!/bin/sh\nexit 3\n")
    job_id = enqueue_nmap(job_session_factory)
    worker = Worker(job_session_factory, "w1")
    assert worker.run_next() == job_id
    assert load(job_session_factory, job_id).status == "queued"
    assert worker.run_next() == job_id
    assert worker.run_next() is None  # no third attempt
    job = load(job_session_factory, job_id)
    assert (job.status, job.error_code, job.attempts) == ("failed", "scanner_failed", 2)
    with job_session_factory() as db:
        assert "retry_scheduled" in [e.type for e in jobs.list_events(db, job_id)]


@pytest.mark.usefixtures("nmap_enabled")
def test_missing_scanner_fails_without_retry(job_session_factory, monkeypatch, job_env, tmp_path):
    monkeypatch.setattr(job_env, "scan_nmap_binary", str(tmp_path / "does-not-exist"))
    job_id = enqueue_nmap(job_session_factory)
    Worker(job_session_factory, "w1").run_next()
    job = load(job_session_factory, job_id)
    assert (job.status, job.error_code, job.attempts) == ("failed", "scanner_missing", 1)


@pytest.mark.usefixtures("nmap_enabled")
def test_scope_is_revalidated_at_execution_time(
    job_session_factory, make_scanner, job_env, monkeypatch, tmp_path
):
    make_scanner("#!/bin/sh\ntouch MARKER\n")
    job_id = enqueue_nmap(job_session_factory)
    # The operator narrowed the authorized scope after the job was queued.
    monkeypatch.setattr(job_env, "scan_allowed_cidrs_raw", "10.99.0.0/24")
    Worker(job_session_factory, "w1").run_next()
    job = load(job_session_factory, job_id)
    assert (job.status, job.error_code, job.attempts) == ("failed", "scope_rejected", 1)
    assert not (tmp_path / "ran").exists()


def test_unexpected_executor_error_is_generic_and_retried(
    job_session_factory, job_env, monkeypatch
):
    monkeypatch.setattr(job_env, "scan_job_max_attempts", 1)

    def boom(ctx):
        raise RuntimeError("super-secret-internal-detail")

    job_id = enqueue(job_session_factory)
    Worker(job_session_factory, "w1", executor=boom).run_next()
    job = load(job_session_factory, job_id)
    assert job.status == "failed" and job.error_code == "internal_error"
    assert "super-secret" not in job.error_message


# ------------------------------------- cancellation / timeout / shutdown

def _start_running_job(factory, tmp_path, worker):
    pidfile = tmp_path / "child.pid"
    job_id = enqueue_nmap(factory)
    thread = threading.Thread(target=worker.run_next, daemon=True)
    thread.start()
    assert wait_for(lambda: read_pid(pidfile) is not None), "scanner did not start"
    return job_id, read_pid(pidfile), thread


@pytest.mark.usefixtures("nmap_enabled")
def test_cancel_kills_the_whole_process_group(job_session_factory, make_scanner, tmp_path):
    make_scanner(SLEEPER_SCRIPT)
    worker = Worker(job_session_factory, "w1")
    job_id, child, thread = _start_running_job(job_session_factory, tmp_path, worker)
    assert alive(child)
    # The group id is persisted so a restarted worker can reap it.
    assert wait_for(lambda: load(job_session_factory, job_id).runner_pid is not None)

    with job_session_factory() as db:
        assert jobs.request_cancel(db, job_id).status == "cancelling"
    thread.join(20)
    assert not thread.is_alive()

    job = load(job_session_factory, job_id)
    assert job.status == "cancelled" and job.runner_pid is None
    assert wait_for(lambda: not alive(child)), "scanner descendant was orphaned"


@pytest.mark.usefixtures("nmap_enabled")
def test_scan_timeout_kills_scanner_and_fails_without_retry(
    job_session_factory, make_scanner, tmp_path, monkeypatch
):
    quick = dataclasses.replace(PROFILES[ScanProfile.SECURITY], timeout_seconds=1)
    monkeypatch.setitem(PROFILES, ScanProfile.SECURITY, quick)
    make_scanner(SLEEPER_SCRIPT)
    job_id = enqueue_nmap(job_session_factory)
    Worker(job_session_factory, "w1").run_next()
    job = load(job_session_factory, job_id)
    assert (job.status, job.error_code, job.attempts) == ("failed", "timeout", 1)
    child = read_pid(tmp_path / "child.pid")
    assert child is not None and wait_for(lambda: not alive(child))


@pytest.mark.usefixtures("nmap_enabled")
def test_worker_shutdown_stops_scanner_and_requeues_without_losing_attempt(
    job_session_factory, make_scanner, tmp_path
):
    make_scanner(SLEEPER_SCRIPT)
    worker = Worker(job_session_factory, "w1")
    job_id, child, thread = _start_running_job(job_session_factory, tmp_path, worker)
    worker.stop()
    thread.join(20)
    assert not thread.is_alive()
    job = load(job_session_factory, job_id)
    assert (job.status, job.attempts, job.lease_owner) == ("queued", 0, None)
    assert wait_for(lambda: not alive(child))


@pytest.mark.usefixtures("nmap_enabled")
def test_lost_lease_stops_the_scanner_without_touching_job_state(
    job_session_factory, make_scanner, tmp_path
):
    make_scanner(SLEEPER_SCRIPT)
    worker = Worker(job_session_factory, "w1")
    job_id, child, thread = _start_running_job(job_session_factory, tmp_path, worker)
    # Another worker's recovery took the job (simulated by expiring the lease).
    with job_session_factory() as db:
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import update
        db.execute(update(ScanJob).where(ScanJob.id == job_id).values(
            lease_expires_at=datetime.now(UTC) - timedelta(seconds=5)))
        db.commit()
        assert jobs.recover(db) == [(job_id, "requeued")]
    thread.join(20)
    assert not thread.is_alive()
    assert wait_for(lambda: not alive(child))
    assert load(job_session_factory, job_id).status == "queued"


def test_restart_recovery_reaps_orphaned_scanner_and_requeues(
    job_session_factory, make_scanner, tmp_path
):
    script = make_scanner("#!/bin/sh\nsleep 300\n")
    job_id = enqueue(job_session_factory)
    # The previous incarnation of worker "w1" died, leaving its scanner behind.
    orphan = subprocess.Popen([str(script)], start_new_session=True)  # noqa: S603
    try:
        with job_session_factory() as db:
            assert jobs.claim_next(db, "w1")
            jobs.set_runner_pid(db, job_id, "w1", orphan.pid)

        assert Worker(job_session_factory, "w1").recover_on_startup() == [(job_id, "requeued")]
        assert orphan.wait(timeout=10) == -signal.SIGKILL
        assert load(job_session_factory, job_id).status == "queued"
    finally:
        if orphan.poll() is None:
            os.killpg(orphan.pid, signal.SIGKILL)
            orphan.wait()


def test_reaper_refuses_unrelated_or_own_processes(make_scanner, tmp_path):
    make_scanner("#!/bin/sh\nexit 0\n")
    other = subprocess.Popen(["sleep", "300"], start_new_session=True)  # noqa: S603,S607
    try:
        assert scan_runner.reap_stale_process_group(other.pid) is False  # not the scanner
        assert scan_runner.reap_stale_process_group(os.getpid()) is False
        assert scan_runner.reap_stale_process_group(None) is False
        assert scan_runner.reap_stale_process_group(1) is False
        assert other.poll() is None
    finally:
        os.killpg(other.pid, signal.SIGKILL)
        other.wait()


# ------------------------------------------------------------- scheduling

def test_tick_respects_the_concurrency_cap(job_session_factory):
    gate = threading.Event()

    def blocked(ctx):
        gate.wait(15)
        return {}

    first = enqueue(job_session_factory)
    second = enqueue(job_session_factory)
    worker = Worker(job_session_factory, "w1", executor=blocked)
    try:
        worker.tick()
        assert wait_for(lambda: load(job_session_factory, first).status == "running")
        worker.tick()
        assert load(job_session_factory, second).status == "queued"
    finally:
        gate.set()
    for t in list(worker._threads.values()):
        t.join(10)
    worker.tick()
    for t in list(worker._threads.values()):
        t.join(10)
    assert load(job_session_factory, first).status == "succeeded"
    assert load(job_session_factory, second).status == "succeeded"
