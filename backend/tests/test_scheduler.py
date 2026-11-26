"""M16 scheduler: deterministic fake clock, no duplicates, fail-closed, shared queue."""
from __future__ import annotations

import os
import random
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app import credentials as creds_svc
from app import jobs, scheduler
from app.connectors.base import ConnectorError
from app.connectors.snmp import ALLOWED_OIDS, MISSING
from app.models import ConnectorSetting, Device, ScanJob, Schedule
from app.worker import Worker

pytestmark = pytest.mark.usefixtures("job_env")
T0 = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


def rng(seed=1):
    return random.Random(seed)  # noqa: S311 - deterministic jitter in tests


def add_schedule(factory, *, kind="scan", targets=("10.77.0.0/28",), interval=600, due=T0,
                 enabled=True, profile="discovery", jitter=10):
    sid = str(uuid.uuid4())
    with factory() as db:
        db.add(Schedule(
            id=sid, name=f"s-{sid[:6]}", kind=kind, profile=profile if kind == "scan" else None,
            targets={"v": list(targets)}, interval_seconds=interval, jitter_percent=jitter,
            enabled=enabled, next_run_at=due, consecutive_failures=0, created_by="test",
            created_at=T0, updated_at=T0))
        db.commit()
    return sid


def run_tick(factory, clock, seed=1):
    with factory() as db:
        return scheduler.tick(db, clock, rng(seed))


def jobs_of(factory):
    with factory() as db:
        return list(db.scalars(select(ScanJob).order_by(ScanJob.created_at)))


def sched(factory, sid):
    with factory() as db:
        s = db.get(Schedule, sid)
        db.expunge(s)
        return s


def test_not_due_does_nothing_then_fires_once_when_due(job_session_factory):
    sid = add_schedule(job_session_factory, due=T0 + timedelta(minutes=5))
    clock = Clock()
    assert run_tick(job_session_factory, clock) == {}
    clock.advance(minutes=6)
    assert run_tick(job_session_factory, clock) == {sid: "enqueued"}
    (job,) = jobs_of(job_session_factory)
    assert job.kind == "scan" and job.created_by == f"schedule:{sid}"
    assert job.status == "queued" and job.targets["v"] == ["10.77.0.0/28"]
    s = sched(job_session_factory, sid)
    assert s.last_job_id == job.id and s.last_run_at == clock.now
    delta = (s.next_run_at - clock.now).total_seconds()
    assert 600 <= delta <= 660  # interval + up to 10% jitter
    assert run_tick(job_session_factory, clock) == {}  # same instant: not due again


def test_stale_scheduler_cannot_duplicate_a_run(job_session_factory):
    sid = add_schedule(job_session_factory)
    clock = Clock()
    with job_session_factory() as a, job_session_factory() as b:
        stale_a, stale_b = a.get(Schedule, sid), b.get(Schedule, sid)
        assert scheduler._fire(a, stale_a, clock.now, rng()) == "enqueued"
        assert scheduler._fire(b, stale_b, clock.now, rng()) == "lost_race"
    assert len(jobs_of(job_session_factory)) == 1


def test_restart_does_not_duplicate(job_session_factory):
    sid = add_schedule(job_session_factory)
    clock = Clock()
    Worker(job_session_factory, "w1", clock=clock).run_scheduler()
    Worker(job_session_factory, "w1-restarted", clock=clock).run_scheduler()
    assert len(jobs_of(job_session_factory)) == 1
    assert sched(job_session_factory, sid).last_job_id


def test_disabled_schedule_creates_no_jobs(job_session_factory):
    add_schedule(job_session_factory, enabled=False)
    assert run_tick(job_session_factory, Clock()) == {}
    assert jobs_of(job_session_factory) == []


def test_missed_runs_are_skipped_not_replayed(job_session_factory):
    sid = add_schedule(job_session_factory, due=T0 - timedelta(days=10), interval=3600)
    clock = Clock()
    assert run_tick(job_session_factory, clock) == {sid: "enqueued"}
    assert len(jobs_of(job_session_factory)) == 1
    assert sched(job_session_factory, sid).next_run_at > clock.now


def test_overlapping_run_is_skipped_until_previous_job_ends(job_session_factory):
    sid = add_schedule(job_session_factory)
    clock = Clock()
    run_tick(job_session_factory, clock)
    clock.advance(hours=1)
    assert run_tick(job_session_factory, clock) == {sid: "overlap_skipped"}
    assert len(jobs_of(job_session_factory)) == 1
    # No longer due immediately: it is retried a minute later, not every tick.
    assert run_tick(job_session_factory, clock) == {}
    assert sched(job_session_factory, sid).next_run_at == clock.now + timedelta(seconds=60)


def test_overlap_skips_do_not_starve_other_schedules(job_session_factory, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "scheduler_max_new_jobs_per_tick", 1)
    monkeypatch.setattr(scheduler.settings, "scan_max_active_jobs", 50)
    busy = add_schedule(job_session_factory, due=T0 - timedelta(hours=2))
    clock = Clock()
    run_tick(job_session_factory, clock)  # busy schedule now has an active job
    clock.advance(hours=3)
    other = add_schedule(job_session_factory, due=clock.now - timedelta(minutes=1))
    with job_session_factory() as db:  # make the busy schedule due again, oldest first
        db.get(Schedule, busy).next_run_at = clock.now - timedelta(hours=1)
        db.commit()
    assert run_tick(job_session_factory, clock) == {busy: "overlap_skipped"}
    assert run_tick(job_session_factory, clock) == {other: "enqueued"}


def test_retries_do_not_recount_the_same_failed_job(job_session_factory, monkeypatch):
    sid = add_schedule(job_session_factory, interval=600, jitter=0)
    clock = Clock()
    run_tick(job_session_factory, clock)
    finish_last(job_session_factory, "failed", clock.now)
    clock.now = sched(job_session_factory, sid).next_run_at
    monkeypatch.setattr(scheduler.settings, "scan_max_active_jobs", 1)
    with job_session_factory() as db:  # fill the shared queue with another active job
        jobs.enqueue_scan(db, profile="discovery", targets=["10.77.0.0/30"], progress_total=2,
                          created_by="ui")
    for _ in range(3):  # repeated queue_full retries
        assert run_tick(job_session_factory, clock)[sid] == "queue_full"
        clock.advance(seconds=60)
    assert sched(job_session_factory, sid).consecutive_failures == 0
    with job_session_factory() as db:
        for j in db.scalars(select(ScanJob).where(ScanJob.created_by == "ui")):
            j.status, j.finished_at = "succeeded", clock.now
        db.commit()
    assert run_tick(job_session_factory, clock)[sid] == "enqueued"
    s = sched(job_session_factory, sid)
    assert s.consecutive_failures == 1  # one failed job -> exactly one failure, x2 backoff
    assert (s.next_run_at - clock.now).total_seconds() == 1200


def finish_last(factory, status, at):
    with factory() as db:
        job = db.scalars(select(ScanJob).order_by(ScanJob.created_at.desc())).first()
        job.status, job.finished_at = status, at
        db.commit()


def test_backoff_after_failures_then_reset_on_success(job_session_factory):
    sid = add_schedule(job_session_factory, interval=600, jitter=0)
    clock = Clock()
    run_tick(job_session_factory, clock)
    for expected_factor in (2, 4):
        finish_last(job_session_factory, "failed", clock.now)
        clock.now = sched(job_session_factory, sid).next_run_at
        run_tick(job_session_factory, clock)
        s = sched(job_session_factory, sid)
        assert (s.next_run_at - clock.now).total_seconds() == 600 * expected_factor
    finish_last(job_session_factory, "succeeded", clock.now)
    clock.now = sched(job_session_factory, sid).next_run_at
    run_tick(job_session_factory, clock)
    s = sched(job_session_factory, sid)
    assert s.consecutive_failures == 0 and (s.next_run_at - clock.now).total_seconds() == 600


def test_backoff_is_capped():
    assert scheduler.next_run(T0, 100, 0, 50, rng()) == T0 + timedelta(seconds=800)


def test_unauthorized_targets_fail_closed(job_session_factory):
    sid = add_schedule(job_session_factory, targets=("10.99.0.0/24",))  # outside the ceiling
    clock = Clock()
    out = run_tick(job_session_factory, clock)
    assert out[sid].startswith("rejected:")
    assert jobs_of(job_session_factory) == []
    s = sched(job_session_factory, sid)
    assert s.last_error_code and s.next_run_at > clock.now


def test_intrusive_profile_never_runs_from_a_schedule(job_session_factory, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "scan_security_profile_enabled", True)
    sid = add_schedule(job_session_factory, profile="security")
    assert run_tick(job_session_factory, Clock())[sid].startswith("rejected")
    assert jobs_of(job_session_factory) == []


def test_queue_full_retries_soon_without_job(job_session_factory, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "scan_max_active_jobs", 1)
    first = add_schedule(job_session_factory)
    second = add_schedule(job_session_factory, due=T0 + timedelta(seconds=1))
    clock = Clock(T0 + timedelta(seconds=5))
    out = run_tick(job_session_factory, clock)
    assert out == {first: "enqueued", second: "queue_full"}
    assert len(jobs_of(job_session_factory)) == 1
    assert sched(job_session_factory, second).next_run_at == clock.now + timedelta(seconds=60)


def test_per_tick_budget(job_session_factory, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "scheduler_max_new_jobs_per_tick", 2)
    monkeypatch.setattr(scheduler.settings, "scan_max_active_jobs", 50)
    for i in range(5):
        add_schedule(job_session_factory, due=T0 - timedelta(minutes=i))
    out = run_tick(job_session_factory, Clock())
    assert len(out) == 2 and len(jobs_of(job_session_factory)) == 2


def test_scheduled_and_ui_jobs_share_one_queue_and_cap(job_session_factory, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "scan_max_active_jobs", 1)
    with job_session_factory() as db:
        jobs.enqueue_scan(db, profile="discovery", targets=["10.77.0.0/30"], progress_total=2,
                          created_by="ui-user")
    sid = add_schedule(job_session_factory)
    assert run_tick(job_session_factory, Clock())[sid] == "queue_full"


# ------------------------------------------------------------- end to end ---


def make_device(factory, ip, last_seen=None):
    did = str(uuid.uuid4())
    with factory() as db:
        db.add(Device(id=did, hostname=f"h-{did[:6]}", ip={"v": [ip]}, roles={"v": []},
                      ports={"v": []}, first_seen=last_seen, last_seen=last_seen))
        db.commit()
    return did


def seen(factory, did):
    with factory() as db:
        return db.get(Device, did).last_seen


def test_scheduled_icmp_scan_updates_last_seen(job_session_factory):
    old = T0 - timedelta(days=1)
    did = make_device(job_session_factory, "10.77.0.5", old)
    add_schedule(job_session_factory, targets=("10.77.0.0/28",))
    clock = Clock()

    def executor(ctx):
        return {"probe": "icmp_echo", "hosts": [{"ip": "10.77.0.5",
                                                 "observed_at": clock.now.isoformat()}]}

    worker = Worker(job_session_factory, "w", executor=executor, clock=clock)
    worker.run_scheduler()
    assert worker.run_next() is not None
    assert seen(job_session_factory, did) == clock.now


def put_snmp_creds(factory, did):
    with factory() as db:
        for ctype, meta, pw in (("snmpv3_auth", {"username": "mon", "protocol": "SHA256"},
                                 "authpass-1234"), ("snmpv3_priv", {"protocol": "AES128"},
                                                    "privpass-1234")):
            creds_svc.upsert(db, creds_svc.Scope.device(did), creds_svc.get_spec(ctype),
                             {"password": pw}, meta)
        db.commit()


class FakeSnmp:
    def __init__(self, fail=False):
        self.fail, self.calls = fail, 0

    async def get(self, target, oids):
        self.calls += 1
        if self.fail:
            raise ConnectorError("timeout", "No response from the SNMP agent")
        return {o: (b"sw" if o == ALLOWED_OIDS["sys_name"] else MISSING) for o in oids}

    async def walk(self, target, oid, *, max_rows, deadline):
        return []


def test_scheduled_snmp_poll_updates_last_seen_only_on_success(job_session_factory):
    old = T0 - timedelta(days=1)
    ok = make_device(job_session_factory, "10.77.0.6", old)
    bad = make_device(job_session_factory, "10.77.0.7", old)
    put_snmp_creds(job_session_factory, ok)
    add_schedule(job_session_factory, kind="snmp_poll", targets=(ok,), interval=120)
    clock = Clock()
    worker = Worker(job_session_factory, "w", clock=clock, snmp_transport=FakeSnmp())
    worker.run_scheduler()
    jid = worker.run_next()
    with job_session_factory() as db:
        job = db.get(ScanJob, jid)
        assert job.kind == "snmp_poll" and job.status == "succeeded"
        assert job.result["polled"] == 1
    assert seen(job_session_factory, ok) > old
    assert seen(job_session_factory, bad) == old


def test_failed_snmp_poll_does_not_touch_last_seen_and_fails_job(job_session_factory):
    old = T0 - timedelta(days=1)
    did = make_device(job_session_factory, "10.77.0.8", old)
    put_snmp_creds(job_session_factory, did)
    add_schedule(job_session_factory, kind="snmp_poll", targets=(did,), interval=120)
    worker = Worker(job_session_factory, "w", clock=Clock(), snmp_transport=FakeSnmp(fail=True))
    worker.run_scheduler()
    jid = worker.run_next()
    with job_session_factory() as db:
        job = db.get(ScanJob, jid)
        assert job.status == "failed" and job.error_code == "poll_failed"
    assert seen(job_session_factory, did) == old


def test_snmp_poll_outside_policy_is_skipped_without_network(job_session_factory):
    did = make_device(job_session_factory, "10.99.9.9")  # outside the 10.77.0.0/24 ceiling
    put_snmp_creds(job_session_factory, did)
    add_schedule(job_session_factory, kind="snmp_poll", targets=(did,), interval=120)
    snmp = FakeSnmp()
    worker = Worker(job_session_factory, "w", clock=Clock(), snmp_transport=snmp)
    worker.run_scheduler()
    worker.run_next()
    assert snmp.calls == 0


class FakeUniFi:
    def __init__(self):
        self.calls = []

    async def get_json(self, path, params=None):
        self.calls.append(path)
        if path.endswith("/sites"):
            return {"data": [{"id": "s1"}], "totalCount": 1}
        if path.endswith("/devices"):
            return {"data": [{"id": "d1", "macAddress": "aa:bb:cc:00:00:01",
                              "ipAddress": "10.77.0.20", "name": "usw", "state": "ONLINE"}],
                    "totalCount": 1}
        return {"data": [], "totalCount": 0}


def test_scheduled_unifi_sync_runs_and_disabled_connector_fails_closed(job_session_factory):
    add_schedule(job_session_factory, kind="unifi_sync", targets=(), interval=120)
    http = FakeUniFi()
    worker = Worker(job_session_factory, "w", clock=Clock(),
                    unifi_http_factory=lambda base, token, verify: http)
    worker.run_scheduler()
    jid = worker.run_next()
    with job_session_factory() as db:
        job = db.get(ScanJob, jid)
        assert job.status == "failed" and job.error_code == "connector_disabled"
    assert http.calls == []

    with job_session_factory() as db:
        db.add(ConnectorSetting(name="unifi", enabled=True, base_url="https://10.77.0.1",
                                verify_tls=True, consecutive_failures=0))
        creds_svc.upsert(db, creds_svc.Scope.connector("unifi"),
                         creds_svc.get_spec("unifi_api_token"),
                         {"token": "UNIFI-TOKEN-0123456789"}, {})
        db.commit()
    with job_session_factory() as db:
        s = db.scalars(select(Schedule)).one()
        s.next_run_at = T0
        s.last_job_id = None
        db.commit()
    worker.run_scheduler()
    jid = worker.run_next()
    with job_session_factory() as db:
        job = db.get(ScanJob, jid)
        assert job.status == "succeeded" and job.result["devices_created"] == 1
        assert db.query(Device).filter_by(mac="aa:bb:cc:00:00:01").count() == 1


# ------------------------------------------------- worker kinds / key boundary ---

def enqueue(factory, kind):
    with factory() as db:
        return jobs.enqueue_scan(db, profile="connector" if kind != "scan" else "discovery",
                                 targets=["10.77.0.0/30"] if kind == "scan" else [],
                                 progress_total=1, created_by="t", kind=kind).id


def test_claim_next_honours_kinds_and_does_not_cross_claim(job_session_factory):
    scan_id = enqueue(job_session_factory, "scan")
    poll_id = enqueue(job_session_factory, "snmp_poll")
    with job_session_factory() as db:
        assert jobs.claim_next(db, "connector", ("snmp_poll", "unifi_sync")).id == poll_id
        assert jobs.claim_next(db, "connector", ("snmp_poll", "unifi_sync")) is None
        assert jobs.claim_next(db, "scanner", ("scan",)).id == scan_id


def test_concurrency_cap_is_counted_per_kind_group(job_session_factory):
    enqueue(job_session_factory, "scan")
    enqueue(job_session_factory, "snmp_poll")
    with job_session_factory() as db:
        assert jobs.claim_next(db, "scanner", ("scan",))         # scan cap (1) reached
        assert jobs.claim_next(db, "connector", ("snmp_poll",))  # polls have their own budget
    enqueue(job_session_factory, "snmp_poll")
    with job_session_factory() as db:
        assert jobs.claim_next(db, "connector", ("snmp_poll",)) is None  # poll cap reached


def test_worker_only_runs_configured_kinds(job_session_factory, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "worker_job_kinds_raw", "scan")
    poll_id = enqueue(job_session_factory, "snmp_poll")
    worker = Worker(job_session_factory, "scanner-only", executor=lambda ctx: {"probe": "x"})
    assert worker.run_next() is None
    with job_session_factory() as db:
        assert db.get(ScanJob, poll_id).status == "queued"


def test_invalid_worker_kinds_are_rejected(monkeypatch):
    monkeypatch.setattr(scheduler.settings, "worker_job_kinds_raw", "scan,rm -rf")
    with pytest.raises(ValueError):
        _ = scheduler.settings.worker_job_kinds


def test_compose_keeps_the_credential_key_out_of_the_scanner_worker(tmp_path):
    import json
    import shutil
    import subprocess
    from pathlib import Path

    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    root = Path(__file__).resolve().parents[2]
    env_file = tmp_path / "env"
    env_file.write_text("APP_ENV=test\n")
    key = tmp_path / "key"
    key.write_text("x")
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "HOME_NOC_ENV_FILE": str(env_file),
           "HOME_NOC_CREDENTIAL_KEY_FILE": str(key)}
    docker = shutil.which("docker")
    done = subprocess.run(  # noqa: S603 - fixed argv
        [docker, "compose", "-f", str(root / "docker-compose.yml"), "config", "--format", "json"],
        capture_output=True, text=True, env=env, check=False, timeout=60)
    if done.returncode != 0:
        pytest.skip(f"docker compose unavailable: {done.stderr[-200:]}")
    services = json.loads(done.stdout)["services"]
    worker, connector = services["worker"], services["connector-worker"]
    assert "secrets" not in worker and "CREDENTIAL_ENCRYPTION_KEY_FILE" not in str(worker)
    assert worker["build"]["target"] == "worker"
    assert worker["environment"]["WORKER_JOB_KINDS"] == "scan"
    assert connector["build"]["target"] == "api"  # no scanner binary in this image
    assert [x["source"] for x in connector["secrets"]] == ["home_noc_credential_key"]
    assert connector["environment"]["WORKER_JOB_KINDS"] == "snmp_poll,unifi_sync"
    assert connector["cap_drop"] == ["ALL"] and connector["read_only"] is True
    assert "ports" not in connector and "ports" not in worker


def test_worker_main_refuses_to_start_with_invalid_job_kinds(monkeypatch):
    from app import worker as worker_module

    monkeypatch.setattr(worker_module.settings, "worker_job_kinds_raw", "snmp-poll")
    assert worker_module.main() == 2
