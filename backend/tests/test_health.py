"""M19 health: pure state transitions, evidence adapters, snapshots, API."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app import health
from app.health import (
    CONFIRM_FAILURES,
    DEGRADED,
    FRESH_SECONDS,
    OFFLINE,
    ONLINE,
    UNKNOWN,
    SourceState,
    evaluate,
)
from app.models import Device, DeviceHealth, HealthSnapshot, ScanJob

T0 = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
S = SourceState


def ago(seconds):
    return T0 - timedelta(seconds=seconds)


# --------------------------------------------------------------- pure rules ---

def test_never_observed_is_unknown():
    assert evaluate({}, T0)[0] == UNKNOWN
    assert evaluate({"icmp": S(None, ago(5), 7)}, T0)[0] == UNKNOWN  # failures alone prove nothing


def test_fresh_success_is_online():
    assert evaluate({"icmp": S(ago(60), ago(60), 0)}, T0)[0] == ONLINE


@pytest.mark.parametrize("source", sorted(FRESH_SECONDS))
def test_freshness_window_is_source_specific(source):
    window = FRESH_SECONDS[source]
    assert evaluate({source: S(ago(window), ago(window), 0)}, T0)[0] == ONLINE
    assert evaluate({source: S(ago(window + 1), ago(window + 1), 0)}, T0)[0] == UNKNOWN


def test_single_failure_never_marks_offline():
    states = {"icmp": S(ago(5000), ago(10), 1)}
    status, reason = evaluate(states, T0)
    assert status == DEGRADED and "not yet confirmed" in reason


def test_confirmed_failures_and_stale_means_offline():
    states = {"icmp": S(ago(5000), ago(10), CONFIRM_FAILURES)}
    assert evaluate(states, T0)[0] == OFFLINE


def test_snmp_only_device_is_not_offline_for_icmp_failures():
    # ICMP never succeeded for this device (blocked): failures there are ignored.
    states = {"snmp": S(ago(60), ago(60), 0), "icmp": S(None, ago(10), 50)}
    assert evaluate(states, T0)[0] == ONLINE


def test_icmp_blocked_after_it_once_worked_degrades_but_does_not_offline():
    states = {"snmp": S(ago(60), ago(60), 0), "icmp": S(ago(99999), ago(10), 10)}
    status, reason = evaluate(states, T0)
    assert status == DEGRADED and "icmp failing" in reason and "snmp" in reason


def test_recent_success_followed_by_confirmed_failures_is_not_fresh():
    # Single source: success 1 minute ago, then 3 consecutive failures -> offline,
    # not "degraded because it is still fresh".
    assert evaluate({"snmp": S(ago(60), ago(1), CONFIRM_FAILURES)}, T0)[0] == OFFLINE
    # With another healthy source it is only degraded.
    both = {"snmp": S(ago(60), ago(1), CONFIRM_FAILURES), "icmp": S(ago(30), ago(30), 0)}
    assert evaluate(both, T0)[0] == DEGRADED


def test_all_sources_failing_and_stale_is_offline():
    states = {"snmp": S(ago(9000), ago(10), 4), "icmp": S(ago(9000), ago(10), 4)}
    assert evaluate(states, T0)[0] == OFFLINE


def test_stale_without_failures_is_unknown_not_offline():
    assert evaluate({"icmp": S(ago(10**6), ago(10**6), 0)}, T0)[0] == UNKNOWN


# ------------------------------------------------------- recording/transitions ---

@pytest.fixture
def db():
    from app.db import Base, SessionLocal, engine

    Base.metadata.create_all(bind=engine)
    s = SessionLocal()
    yield s
    s.query(HealthSnapshot).delete()
    s.query(DeviceHealth).delete()
    s.query(ScanJob).delete()
    s.query(Device).delete()
    s.commit()
    s.close()


def device(db, ip="10.0.0.5"):
    did = str(uuid.uuid4())
    db.add(Device(id=did, hostname=f"h-{did[:5]}", ip={"v": [ip]}, roles={"v": []},
                  ports={"v": []}))
    db.commit()
    return did


def test_state_machine_online_degraded_offline_and_recovery(db):
    did = device(db)
    health.record(db, did, "snmp", True, T0)
    health.record(db, did, "icmp", True, T0)
    assert db.get(DeviceHealth, did).status == ONLINE
    t = T0
    for i in range(CONFIRM_FAILURES):  # SNMP starts failing; ICMP still fresh
        t = T0 + timedelta(minutes=i + 1)
        health.record(db, did, "snmp", False, t)
    assert db.get(DeviceHealth, did).status == DEGRADED
    # ICMP fails repeatedly too and both go stale
    late = T0 + timedelta(hours=2)
    for i in range(CONFIRM_FAILURES):
        health.record(db, did, "icmp", False, late + timedelta(seconds=i))
    assert db.get(DeviceHealth, did).status == OFFLINE
    health.record(db, did, "snmp", True, late + timedelta(minutes=5))
    row = db.get(DeviceHealth, did)
    assert row.status == DEGRADED  # snmp ok again, icmp still confirmed-failing
    health.record(db, did, "icmp", True, late + timedelta(minutes=6))
    assert db.get(DeviceHealth, did).status == ONLINE
    statuses = [s.status for s in db.scalars(select(HealthSnapshot).order_by(HealthSnapshot.at))]
    assert statuses == [ONLINE, DEGRADED, OFFLINE, DEGRADED, ONLINE]


def test_out_of_order_evidence_is_ignored(db):
    did = device(db)
    health.record(db, did, "icmp", True, T0)
    health.record(db, did, "icmp", False, T0 - timedelta(hours=1))
    assert load(db, did)["icmp"].failures == 0


def load(db, did):
    return health.load_sources(db.get(DeviceHealth, did).sources)


def test_authoritative_failure_confirms_immediately(db):
    did = device(db)
    health.record(db, did, "unifi", True, T0)
    health.record(db, did, "unifi", False, T0 + timedelta(hours=1), authoritative=True)
    assert db.get(DeviceHealth, did).status == OFFLINE


def test_sweep_ages_online_devices_into_unknown(db):
    did = device(db)
    health.record(db, did, "icmp", True, T0)
    assert health.sweep(db, T0 + timedelta(seconds=60)) == 0
    assert health.sweep(db, T0 + timedelta(hours=1)) == 1
    assert db.get(DeviceHealth, did).status == UNKNOWN


def test_snapshots_on_change_plus_hourly_heartbeat_and_pruning(db, monkeypatch):
    did = device(db)
    health.record(db, did, "icmp", True, T0)
    health.record(db, did, "icmp", True, T0 + timedelta(minutes=5))  # no change, no heartbeat
    assert db.query(HealthSnapshot).count() == 1
    health.record(db, did, "icmp", True, T0 + timedelta(minutes=70))  # heartbeat
    assert db.query(HealthSnapshot).count() == 2
    monkeypatch.setattr(health, "MAX_SNAPSHOTS_PER_DEVICE", 3)
    for i in range(10):
        health.record(db, did, "icmp", True, T0 + timedelta(hours=2 + i * 2))
    assert db.query(HealthSnapshot).count() == 3


def test_unknown_source_rejected(db):
    with pytest.raises(ValueError):
        health.record(db, device(db), "carrier-pigeon", True, T0)


# ------------------------------------------------------------ adapters ---------

def test_observation_adapter():
    f = health.source_for_observation
    assert f("snmp", {}) == ("snmp", True, False)
    assert f("scan", {"probe": "icmp_echo"}) == ("icmp", True, False)
    assert f("scan", {"probe": "tcp_connect"}) is None
    assert f("api", {"connector": "unifi", "kind": "device", "state": "ONLINE"}) == \
        ("unifi", True, False)
    assert f("api", {"connector": "unifi", "kind": "device", "state": "OFFLINE"}) == \
        ("unifi", False, True)
    assert f("api", {"connector": "unifi", "kind": "device", "state": "ADOPTING"}) is None
    assert f("manual", {}) is None


def test_snmp_error_codes(db):
    did = device(db)
    health.record(db, did, "snmp", True, T0)
    for code in ("authentication_failed", "access_denied", "credentials_incomplete"):
        health.record_snmp_error(db, did, code, T0 + timedelta(minutes=1))
    assert load(db, did)["snmp"].failures == 0  # the device answered; not unreachable
    health.record_snmp_error(db, did, "timeout", T0 + timedelta(minutes=2))
    assert load(db, did)["snmp"].failures == 1


def test_icmp_sweep_records_unanswered_known_devices_only_in_targets(db):
    from app.reconcile import persist_icmp_scan_result

    up, down, outside = device(db, "10.0.0.5"), device(db, "10.0.0.6"), device(db, "10.9.9.9")
    job = ScanJob(id="j1", kind="scan", profile="discovery", targets={"v": ["10.0.0.0/28"]},
                  status="running", created_by="t", created_at=T0, updated_at=T0,
                  available_at=T0, attempts=1, max_attempts=3, cancel_requested=False,
                  progress_total=14, progress_done=0)
    db.add(job)
    db.commit()
    result = {"probe": "icmp_echo", "hosts": [{"ip": "10.0.0.5",
                                               "observed_at": datetime.now(UTC).isoformat()}]}
    persist_icmp_scan_result(db, "j1", result)
    db.commit()
    assert result["health"] == {"icmp_unanswered": 1}
    assert db.get(DeviceHealth, up).status == ONLINE
    assert load(db, down) == {"icmp": SourceState(None, load(db, down)["icmp"].last_attempt, 1)}
    assert db.get(DeviceHealth, outside) is None
    assert db.get(DeviceHealth, down).status == UNKNOWN  # one blocked ping is not "offline"


# ------------------------------------------------------------------ API --------

URL = "/api/v1/health/devices"


def test_health_api_requires_session(anon_client):
    assert anon_client.get(URL).status_code in (401, 403)


def test_health_api_summary_filter_and_detail(client, db):
    from app.db import SessionLocal

    online = device(db, "10.20.0.1")
    never = device(db, "10.20.0.2")
    health.record(db, online, "snmp", True, datetime.now(UTC))
    db.commit()
    body = client.get(URL).json()
    assert body["summary"]["total"] == 2 and body["summary"]["online"] == 1
    assert body["summary"]["unknown"] == 1 and body["freshness_seconds"]["snmp"] == 900
    by_id = {d["device_id"]: d for d in body["devices"]}
    assert by_id[online]["status"] == "online" and by_id[online]["last_seen"] is None
    assert by_id[never]["status"] == "unknown" and by_id[never]["sources"] == {}
    assert [d["device_id"] for d in client.get(URL + "?status=online").json()["devices"]] == \
        [online]
    assert [d["device_id"] for d in client.get(URL + "?status=unknown").json()["devices"]] == \
        [never]
    assert client.get(URL + "?status=bogus").status_code == 422
    detail = client.get(f"/api/v1/devices/{online}/health").json()
    assert detail["status"] == "online" and detail["snapshots"][0]["status"] == "online"
    assert client.get("/api/v1/devices/nope/health").status_code == 404
    with SessionLocal() as s:
        assert s.get(DeviceHealth, online) is not None


@pytest.mark.usefixtures("job_env")
def test_worker_sweep_ages_statuses_with_its_clock(job_session_factory):
    from app.worker import Worker

    with job_session_factory() as s:
        did = str(uuid.uuid4())
        s.add(Device(id=did, hostname="h", ip={"v": ["10.77.0.2"]}, roles={"v": []},
                     ports={"v": []}))
        s.commit()
        health.record(s, did, "icmp", True, T0)
        s.commit()
    clock = {"now": T0 + timedelta(seconds=30)}
    worker = Worker(job_session_factory, "w", clock=lambda: clock["now"])
    assert worker.run_health_sweep(force=True) == 0
    clock["now"] = T0 + timedelta(hours=3)
    assert worker.run_health_sweep() == 0  # throttled: once a minute of wall time
    assert worker.run_health_sweep(force=True) == 1
    with job_session_factory() as s:
        assert s.get(DeviceHealth, did).status == UNKNOWN


def test_tcp_open_port_records_tcp_health_evidence_but_closed_ports_do_not(db):
    from app.port_observations import persist_tcp_scan_result

    up, closed = device(db, "10.0.1.1"), device(db, "10.0.1.2")
    now = datetime.now(UTC).isoformat()
    result = {"probe": "tcp_connect", "finished_at": now, "observations": [
        {"host": "10.0.1.1", "port": 443, "protocol": "tcp", "state": "open", "observed_at": now},
        {"host": "10.0.1.2", "port": 22, "protocol": "tcp", "state": "refused", "observed_at": now},
    ]}
    persist_tcp_scan_result(db, "job-t", result)
    db.commit()
    assert db.get(DeviceHealth, up).status == ONLINE
    assert load(db, up)["tcp"].failures == 0
    assert db.get(DeviceHealth, closed) is None


@pytest.mark.usefixtures("job_env")
def test_scheduled_snmp_timeouts_confirm_failure_only_after_repeats(job_session_factory):
    from app import connector_jobs
    from app import credentials as creds_svc
    from app.connectors.base import ConnectorError
    from app.scan_runner import JobContext

    did = str(uuid.uuid4())
    with job_session_factory() as s:
        s.add(Device(id=did, hostname="sw", ip={"v": ["10.77.0.9"]}, roles={"v": []},
                     ports={"v": []}))
        for ctype, meta, pw in (
                ("snmpv3_auth", {"username": "m", "protocol": "SHA256"}, "authpass-1234"),
                ("snmpv3_priv", {"protocol": "AES128"}, "privpass-1234")):
            creds_svc.upsert(s, creds_svc.Scope.device(did), creds_svc.get_spec(ctype),
                             {"password": pw}, meta)
        health.record(s, did, "snmp", True, T0)
        s.commit()

    class Dead:
        async def get(self, target, oids):
            raise ConnectorError("timeout", "No response from the SNMP agent")

        async def walk(self, *a, **k):
            return []

    ctx = JobContext(job_id="j", profile="connector", targets=[did], attempt=1,
                     check=lambda: None, progress=lambda d, t: None, event=lambda t, m: None,
                     set_pid=lambda p: None, kind="snmp_poll")
    from app.scan_runner import RunnerError

    for _ in range(CONFIRM_FAILURES):
        with pytest.raises(RunnerError):
            connector_jobs.run_snmp_poll(ctx, job_session_factory, Dead())
    with job_session_factory() as s:
        assert health.load_sources(s.get(DeviceHealth, did).sources)["snmp"].failures == \
            CONFIRM_FAILURES


def test_snmp_poll_route_failure_records_health(client):
    from app.api.v1.routers.snmp import get_snmp_transport
    from app.connectors.base import ConnectorError
    from app.main import app

    class Dead:
        async def get(self, target, oids):
            raise ConnectorError("timeout", "No response from the SNMP agent")

        async def walk(self, *a, **k):
            return []

    app.dependency_overrides[get_snmp_transport] = lambda: Dead()
    try:
        dev = client.post("/api/v1/devices", json={"hostname": "r1", "ip": ["10.20.40.7"]},
                          headers=client.csrf_headers).json()["id"]
        for kind, pw in (("snmpv3_auth", {"password": "authpass-1234"}),
                         ("snmpv3_priv", {"password": "privpass-1234"})):
            meta = {"username": "m", "protocol": "SHA256"} if kind == "snmpv3_auth" else \
                {"protocol": "AES128"}
            resp = client.put(f"/api/v1/credentials/devices/{dev}/{kind}",
                              headers=client.csrf_headers, json={"secret": pw, "metadata": meta})
            assert resp.status_code in (200, 201)
        r = client.post(f"/api/v1/devices/{dev}/snmp/poll", json={}, headers=client.csrf_headers)
        assert r.json()["ok"] is False
    finally:
        app.dependency_overrides.pop(get_snmp_transport, None)
    from app.db import SessionLocal

    with SessionLocal() as s:
        row = s.get(DeviceHealth, dev)
        assert row is not None
        assert health.load_sources(row.sources)["snmp"].failures == 1


def _icmp_job(db, targets=("10.0.0.0/28",)):
    db.add(ScanJob(id="jx", kind="scan", profile="discovery", targets={"v": list(targets)},
                   status="running", created_by="t", created_at=T0, updated_at=T0,
                   available_at=T0, attempts=1, max_attempts=3, cancel_requested=False,
                   progress_total=14, progress_done=0))
    db.commit()


def test_ambiguous_responding_ip_does_not_charge_either_device(db):
    from app.reconcile import persist_icmp_scan_result

    a, b = device(db, "10.0.0.5"), device(db, "10.0.0.5")  # same address, reused (DHCP collision)
    quiet = device(db, "10.0.0.6")
    _icmp_job(db)
    for _ in range(CONFIRM_FAILURES):
        result = {"probe": "icmp_echo", "hosts": [
            {"ip": "10.0.0.5", "observed_at": datetime.now(UTC).isoformat()}]}
        persist_icmp_scan_result(db, "jx", result)
        db.commit()
        assert result["asset_reconciliation"]["ambiguous"] == 1
    for dev in (a, b):
        row = db.get(DeviceHealth, dev)
        assert row is None or "icmp" not in row.sources
    assert load(db, quiet)["icmp"].failures == CONFIRM_FAILURES  # genuinely silent device


def test_truncated_icmp_result_records_no_misses(db):
    from app.reconcile import persist_icmp_scan_result

    quiet = device(db, "10.0.0.7")
    _icmp_job(db)
    result = {"probe": "icmp_echo", "truncated": True, "hosts": []}
    persist_icmp_scan_result(db, "jx", result)
    db.commit()
    assert result["health"] == {"icmp_unanswered": 0, "skipped": "truncated"}
    assert db.get(DeviceHealth, quiet) is None
