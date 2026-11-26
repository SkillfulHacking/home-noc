"""M26 end-to-end pipeline on a synthetic fixture network (no real packets).

ping -> port scan -> deduplicated inventory -> SNMP + UniFi enrichment -> Nuclei findings,
driven through the real queue, worker, reconciliation, health, events and findings code.
Network edges are replaced by fixtures: executor results for ICMP/TCP, a fake SNMPv3
transport, a mocked UniFi API, and a scripted Nuclei binary.
"""
from __future__ import annotations

import json
import time
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app import credentials as creds_svc
from app import jobs
from app.connectors.snmp import ALLOWED_OIDS, MISSING
from app.connectors.snmp_interfaces import IF_COLUMNS as C
from app.models import (
    ConnectorSetting,
    Device,
    DeviceHealth,
    DeviceObservation,
    Event,
    Finding,
    ScanJob,
)
from app.scan_runner import RunnerError
from app.worker import Worker
from tests.test_nuclei import FINDING, env, plan_for, write_fake  # noqa: F401 - env is a fixture
from tests.test_unifi_connector import FakeHttp

pytestmark = pytest.mark.usefixtures("job_env")

SWITCH_IP, HOST_IP, AP_IP = "10.77.0.6", "10.77.0.5", "10.77.0.7"
SWITCH_MAC, AP_MAC = "aa:bb:cc:00:00:06", "aa:bb:cc:00:00:07"
SECRETS = ("AUTH-PASSPHRASE-MARKER-123", "PRIV-PASSPHRASE-MARKER-456", "UNIFI-TOKEN-MARKER-789")


class FakeSnmp:
    """An SNMPv3 agent for a two-port switch."""

    async def get(self, target, oids):
        values = {
            ALLOWED_OIDS["sys_name"]: b"core-switch", ALLOWED_OIDS["sys_services"]: 6,
            ALLOWED_OIDS["ip_forwarding"]: 2,
            ALLOWED_OIDS["bridge_address"]: bytes.fromhex(SWITCH_MAC.replace(":", "")),
            ALLOWED_OIDS["sys_object_id"]: "1.3.6.1.4.1.41112.1.6",
        }
        return {o: values.get(o, MISSING) for o in oids}

    async def walk(self, target, oid, *, max_rows, deadline):
        tables = {
            C["name"]: [(f"{C['name']}.{i}", f"Port {i}".encode()) for i in (1, 2)],
            C["type"]: [(f"{C['type']}.{i}", 6) for i in (1, 2)],
            C["oper_status"]: [(f"{C['oper_status']}.{i}", 1) for i in (1, 2)],
        }
        return tables.get(oid, [])


def unifi_devices():
    return [
        {"id": "u-sw", "macAddress": SWITCH_MAC, "ipAddress": SWITCH_IP, "name": "usw-core",
         "model": "USW-24", "state": "ONLINE", "features": ["switching"]},
        {"id": "u-ap", "macAddress": AP_MAC, "ipAddress": AP_IP, "name": "uap-lounge",
         "model": "U6-Pro", "state": "ONLINE", "features": ["accessPoint"]},
    ]


def executor(ctx):
    now = datetime.now(UTC).isoformat()
    if ctx.profile == "discovery":
        return {"probe": "icmp_echo", "hosts": [{"ip": ip, "observed_at": now}
                                                for ip in (HOST_IP, SWITCH_IP)]}
    if ctx.profile == "ports":
        return {"probe": "tcp_connect", "finished_at": now, "observations": [
            {"host": HOST_IP, "port": 80, "protocol": "tcp", "state": "open", "observed_at": now},
            {"host": SWITCH_IP, "port": 22, "protocol": "tcp", "state": "open", "observed_at": now},
            {"host": SWITCH_IP, "port": 23, "protocol": "tcp", "state": "refused",
             "observed_at": now},
        ]}
    raise AssertionError(f"unexpected profile {ctx.profile}")


@pytest.fixture
def stack(job_session_factory, env):  # noqa: F811 - env fixture from test_nuclei
    http = FakeHttp(devices=unifi_devices())
    worker = Worker(job_session_factory, "pipeline", executor=executor, snmp_transport=FakeSnmp(),
                    unifi_http_factory=lambda base, token, verify: http)
    return worker, job_session_factory


def queue(factory, profile="discovery", kind="scan", targets=("10.77.0.0/28",), **extra):
    with factory() as db:
        return jobs.enqueue_scan(db, profile=profile, kind=kind, targets=list(targets),
                                 progress_total=1, created_by="e2e",
                                 targets_extra=extra or None).id


def run_job(worker, factory, job_id):
    assert worker.run_next() == job_id
    with factory() as db:
        return db.get(ScanJob, job_id)


def device_at(db, ip):
    found = [d for d in db.scalars(select(Device)) if ip in (d.ip or {}).get("v", [])]
    assert len(found) == 1, f"{ip}: {len(found)} devices"
    return found[0]


def store_secrets(factory, switch_id):
    with factory() as db:
        for ctype, meta, pw in (("snmpv3_auth", {"username": "monitor", "protocol": "SHA256"},
                                 SECRETS[0]), ("snmpv3_priv", {"protocol": "AES128"}, SECRETS[1])):
            creds_svc.upsert(db, creds_svc.Scope.device(switch_id), creds_svc.get_spec(ctype),
                             {"password": pw}, meta)
        creds_svc.upsert(db, creds_svc.Scope.connector("unifi"),
                         creds_svc.get_spec("unifi_api_token"), {"token": SECRETS[2]}, {})
        db.add(ConnectorSetting(name="unifi", enabled=True, base_url="https://10.77.0.1",
                                verify_tls=False, consecutive_failures=0))
        db.commit()


def test_full_pipeline_ping_ports_enrichment_findings(stack, env):  # noqa: F811
    worker, factory = stack

    # 1. ping sweep discovers two hosts
    assert run_job(worker, factory, queue(factory, "discovery")).status == "succeeded"
    with factory() as db:
        assert db.query(Device).count() == 2
        switch = device_at(db, SWITCH_IP)
        switch_id = switch.id
        assert switch.last_seen is not None and switch.mac is None

    # 2. port scan adds open ports (refused is not an open port) and re-run does not duplicate
    for _ in range(2):
        assert run_job(worker, factory, queue(factory, "ports")).status == "succeeded"
    with factory() as db:
        assert db.query(Device).count() == 2
        ports = {p["port"] for p in device_at(db, SWITCH_IP).ports["v"]}
        assert ports == {22}
        assert {p["port"] for p in device_at(db, HOST_IP).ports["v"]} == {80}

    # 3. SNMP enriches the switch (role from MIB semantics, interfaces captured, MAC untouched)
    store_secrets(factory, switch_id)
    job = run_job(worker, factory, queue(factory, "connector", "snmp_poll", targets=(switch_id,)))
    assert job.status == "succeeded" and job.result["polled"] == 1
    with factory() as db:
        switch = db.get(Device, switch_id)
        assert switch.roles == {"v": ["switch"]} and switch.mac is None
        obs = db.scalar(select(DeviceObservation).where(DeviceObservation.device_id == switch_id,
                                                        DeviceObservation.source == "snmp"))
        assert [i["name"] for i in obs.data["extra"]["interfaces"]] == ["Port 1", "Port 2"]

    # 4. UniFi merges into the SAME switch (by IP, then binds MAC/vendor) and adds the AP
    job = run_job(worker, factory, queue(factory, "connector", "unifi_sync", targets=()))
    assert job.status == "succeeded", job.error_message
    with factory() as db:
        assert db.query(Device).count() == 3  # no duplicate of the switch
        switch = db.get(Device, switch_id)
        assert switch.mac == SWITCH_MAC and switch.vendor == "Ubiquiti"
        # The derived role is kept; reconciliation never overwrites curated fields.
        assert switch.roles == {"v": ["switch"]}
        assert device_at(db, AP_IP).model == "U6-Pro"
        assert db.query(Device).filter_by(mac=SWITCH_MAC).count() == 1

    # 5. an approved Nuclei run produces a finding on the known HTTP service
    finding_line = {**FINDING, "host": HOST_IP, "url": f"http://{HOST_IP}:80",
                    "matched-at": f"http://{HOST_IP}:80/"}
    write_fake(env, f"cat <<'EOF'\n{json.dumps(finding_line)}\nEOF\n")
    digest = plan_for(factory)["approval_digest"]
    job = run_job(worker, factory, queue(factory, "vuln", approval=digest))
    assert job.status == "succeeded", job.error_message
    with factory() as db:
        (finding,) = db.scalars(select(Finding)).all()
        assert finding.device_id == device_at(db, HOST_IP).id and finding.status == "open"

    # health, events and secrecy across the whole run
    with factory() as db:
        statuses = {d.status for d in db.scalars(select(DeviceHealth))}
        assert statuses == {"online"}
        kinds = [e.type for e in db.scalars(select(Event))]
        assert kinds.count("device_discovered") == 3 and "port_opened" in kinds
        jobs_dump = [[j.result, j.error_message, j.targets] for j in db.scalars(select(ScanJob))]
        dump = json.dumps(jobs_dump
                          + [o.data for o in db.scalars(select(DeviceObservation))]
                          + [f.details for f in db.scalars(select(Finding))]
                          + [[e.summary, e.details] for e in db.scalars(select(Event))],
                          default=str)
        for secret in SECRETS:
            assert secret not in dump


def test_cancel_stops_a_running_job_and_leaves_the_inventory_untouched(stack):
    worker, factory = stack
    started = {"flag": False}

    def slow(ctx):
        started["flag"] = True
        for _ in range(200):
            ctx.check()
            time.sleep(0.05)
        return {"probe": "icmp_echo", "hosts": [{"ip": HOST_IP}]}

    worker.executor = slow
    job_id = queue(factory, "discovery")
    import threading

    thread = threading.Thread(target=worker.run_next)
    thread.start()
    deadline = time.monotonic() + 10
    while not started["flag"] and time.monotonic() < deadline:
        time.sleep(0.02)
    with factory() as db:
        assert jobs.request_cancel(db, job_id).status == "cancelling"
    thread.join(timeout=15)
    with factory() as db:
        assert db.get(ScanJob, job_id).status == "cancelled"
        assert db.query(Device).count() == 0


def test_timeout_fails_the_job_without_retry_and_without_inventory_changes(stack):
    worker, factory = stack

    def timing_out(ctx):
        raise RunnerError("timeout", "Scan exceeded its time limit", retryable=False)

    worker.executor = timing_out
    job = run_job(worker, factory, queue(factory, "discovery"))
    assert job.status == "failed" and job.error_code == "timeout" and job.attempts == 1
    with factory() as db:
        assert db.query(Device).count() == 0


def test_a_crashing_executor_is_retried_then_fails_and_never_corrupts_inventory(stack):
    worker, factory = stack

    def crash(ctx):
        raise ValueError("boom with 10.77.0.5 inside")

    worker.executor = crash
    job_id = queue(factory, "discovery")
    for _ in range(3):
        worker.run_next()
    with factory() as db:
        job = db.get(ScanJob, job_id)
        assert job.status == "failed" and job.error_code == "internal_error"
        assert "boom" not in (job.error_message or "")  # raw exception text is never stored
        assert db.query(Device).count() == 0


def test_restart_recovers_a_job_abandoned_mid_run_without_duplicating_inventory(stack):
    worker, factory = stack
    job_id = queue(factory, "discovery")
    with factory() as db:
        assert jobs.claim_next(db, "pipeline").id == job_id  # a worker "dies" holding the lease
        row = db.get(ScanJob, job_id)
        row.lease_expires_at = datetime(2020, 1, 1, tzinfo=UTC)
        db.commit()
    restarted = Worker(factory, "pipeline", executor=executor)
    restarted.recover_on_startup()
    assert restarted.run_next() == job_id
    with factory() as db:
        assert db.get(ScanJob, job_id).status == "succeeded"
        assert db.query(Device).count() == 2


def test_scheduler_fault_does_not_stop_job_processing(stack, monkeypatch):
    worker, factory = stack
    from app import scheduler

    monkeypatch.setattr(scheduler, "tick", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    job_id = queue(factory, "discovery")
    assert worker.run_scheduler() == {}
    assert run_job(worker, factory, job_id).status == "succeeded"
