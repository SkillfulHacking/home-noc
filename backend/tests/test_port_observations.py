"""M11 asset port observations and owned-job transaction regressions."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app import jobs
from app.jobs import JobStatus
from app.models import Device, DeviceObservation, ScanJob
from app.port_observations import persist_tcp_scan_result
from app.schemas import new_id
from app.worker import Worker

pytestmark = pytest.mark.usefixtures("job_env")


def add_device(factory, *ips, ports=None):
    device_id = new_id()
    with factory() as db:
        db.add(Device(
            id=device_id, hostname=f"asset-{device_id[:8]}",
            ip={"v": list(ips)}, ports={"v": list(ports or [])},
        ))
        db.commit()
    return device_id


def scan_result(*entries, finished=None):
    at = (finished or datetime.now(UTC)).isoformat()
    return {
        "probe": "tcp_connect", "finished_at": at,
        "observations": [
            {
                "host": host, "port": port, "protocol": "tcp",
                "state": state, "observed_at": at,
            }
            for host, port, state in entries
        ],
    }


def observations_for(factory, device_id):
    with factory() as db:
        return list(db.scalars(
            select(DeviceObservation).where(DeviceObservation.device_id == device_id)
            .order_by(DeviceObservation.source_ref)
        ))


def test_open_ports_append_without_destroying_manual_values(job_session_factory):
    manual = {"port": 2222, "proto": "tcp", "service": "ssh-alt", "state": "open"}
    id_ = add_device(job_session_factory, "10.77.0.12", ports=[manual])
    result = scan_result(("10.77.0.12", 443, "open"),
                         ("10.77.0.12", 80, "refused"),
                         ("10.77.0.12", 22, "timeout"))
    with job_session_factory() as db:
        persist_tcp_scan_result(db, "job-1", result)
        db.commit()
    assert result["asset_persistence"]["matched_assets"] == 1
    assert result["asset_persistence"]["canonical_ports_added"] == 1
    with job_session_factory() as db:
        ports = db.get(Device, id_).ports["v"]
        assert manual in ports
        assert {p["port"] for p in ports} == {2222, 443}
    rows = observations_for(job_session_factory, id_)
    assert len(rows) == 1
    assert [x["state"] for x in rows[0].data["ports"]] == ["timeout", "refused", "open"]


def test_same_job_replay_is_idempotent(job_session_factory):
    id_ = add_device(job_session_factory, "10.77.0.5")
    for _ in range(2):
        result = scan_result(("10.77.0.5", 443, "open"))
        with job_session_factory() as db:
            persist_tcp_scan_result(db, "job-replayed", result)
            db.commit()
    assert len(observations_for(job_session_factory, id_)) == 1
    with job_session_factory() as db:
        assert len(db.get(Device, id_).ports["v"]) == 1


def test_multi_ip_asset_retains_each_host_from_one_job(job_session_factory):
    id_ = add_device(job_session_factory, "10.77.0.5", "10.77.0.6")
    result = scan_result(("10.77.0.5", 22, "open"),
                         ("10.77.0.6", 443, "open"))
    with job_session_factory() as db:
        persist_tcp_scan_result(db, "job-multi", result)
        db.commit()
    rows = observations_for(job_session_factory, id_)
    assert len(rows) == 2
    assert {row.data["host"] for row in rows} == {"10.77.0.5", "10.77.0.6"}
    assert result["asset_persistence"]["matched_assets"] == 1
    with job_session_factory() as db:
        assert {x["port"] for x in db.get(Device, id_).ports["v"]} == {22, 443}


def test_ambiguous_and_unknown_hosts_do_not_mutate_assets(job_session_factory):
    first = add_device(job_session_factory, "10.77.0.8")
    second = add_device(job_session_factory, "10.77.0.8")
    result = scan_result(("10.77.0.8", 22, "open"),
                         ("10.77.0.9", 443, "open"))
    with job_session_factory() as db:
        persist_tcp_scan_result(db, "job-ambiguous", result)
        db.commit()
    assert result["asset_persistence"] == {
        "matched_assets": 0, "canonical_ports_added": 0,
        "unmatched_hosts": 1, "ambiguous_hosts": 1,
    }
    assert not observations_for(job_session_factory, first)
    assert not observations_for(job_session_factory, second)


def test_existing_curated_port_is_not_rewritten(job_session_factory):
    curated = {"port": 443, "proto": "tcp", "service": "custom", "state": "closed"}
    id_ = add_device(job_session_factory, "10.77.0.5", ports=[curated])
    result = scan_result(("10.77.0.5", 443, "open"))
    with job_session_factory() as db:
        persist_tcp_scan_result(db, "job-curated", result)
        db.commit()
    with job_session_factory() as db:
        assert db.get(Device, id_).ports["v"] == [curated]
    assert observations_for(job_session_factory, id_)[0].data["ports"][0]["state"] == "open"


def test_old_scan_history_is_pruned_without_touching_other_sources(
    job_session_factory, monkeypatch
):
    from app import port_observations
    monkeypatch.setattr(port_observations, "MAX_TCP_OBSERVATIONS_PER_DEVICE", 2)
    id_ = add_device(job_session_factory, "10.77.0.5")
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with job_session_factory() as db:
        db.add(DeviceObservation(
            id=new_id(), device_id=id_, source="manual", source_ref="operator",
            observed_at=start, data={"note": "keep"},
        ))
        db.commit()
    for n in range(3):
        result = scan_result(("10.77.0.5", 22, "open"),
                             finished=start + timedelta(minutes=n))
        with job_session_factory() as db:
            persist_tcp_scan_result(db, f"job-{n}", result)
            db.commit()
    rows = observations_for(job_session_factory, id_)
    assert len(rows) == 3
    assert sum(row.source == "scan" for row in rows) == 2
    assert any(row.source == "manual" for row in rows)


def test_job_result_enrichment_persisted_atomically(job_session_factory):
    id_ = add_device(job_session_factory, "10.77.0.5")
    result = scan_result(("10.77.0.5", 443, "open"))
    with job_session_factory() as db:
        job_id = jobs.enqueue_scan(
            db, profile="ports", targets=["10.77.0.5"],
            progress_total=1, created_by="tester",
        ).id
    worker = Worker(job_session_factory, "worker-test", executor=lambda _: result)
    assert worker.run_next() == job_id
    with job_session_factory() as db:
        job = db.get(ScanJob, job_id)
        assert job.status == "succeeded"
        assert job.result["asset_persistence"]["matched_assets"] == 1
        assert job.result["asset_persistence"]["canonical_ports_added"] == 1
        assert any(x["port"] == 443 for x in db.get(Device, id_).ports["v"])
    assert len(observations_for(job_session_factory, id_)) == 1


def test_persistence_failure_rolls_back_terminal_transition(job_session_factory):
    add_device(job_session_factory, "10.77.0.5")
    with job_session_factory() as db:
        job_id = jobs.enqueue_scan(
            db, profile="ports", targets=["10.77.0.5"],
            progress_total=1, created_by="tester",
        ).id
    with job_session_factory() as db:
        assert jobs.claim_next(db, "worker-test") is not None
    with pytest.raises(RuntimeError, match="transaction check"):
        with job_session_factory() as db:
            jobs.finish(
                db, job_id, "worker-test", JobStatus.SUCCEEDED,
                result=scan_result(("10.77.0.5", 443, "open")),
                before_commit=lambda _db: (_ for _ in ()).throw(
                    RuntimeError("transaction check")
                ),
            )
    with job_session_factory() as db:
        assert db.get(ScanJob, job_id).status == "running"
        assert db.get(ScanJob, job_id).result is None
