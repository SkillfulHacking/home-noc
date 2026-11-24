"""M12 observation reconciliation: merges, conflicts, churn and stale data."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.models import Device, DeviceIdentity, DeviceObservation
from app.reconcile import (
    AmbiguousObservation,
    ReconcileObservation,
    persist_icmp_scan_result,
    reconcile_observation,
)

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
API = "/api/v1/devices"


def obs(**kw):
    kw.setdefault("source", "snmp")
    kw.setdefault("observed_at", T0)
    return ReconcileObservation(**kw)


def run(factory, **kw):
    with factory() as db:
        result = reconcile_observation(db, obs(**kw))
        db.commit()
        return result


def devices(factory):
    with factory() as db:
        return list(db.scalars(select(Device)))


def rows(factory, device_id):
    with factory() as db:
        return list(db.scalars(
            select(DeviceObservation).where(DeviceObservation.device_id == device_id)
        ))


def test_two_sources_for_one_switch_make_one_asset(job_session_factory):
    f = job_session_factory
    a = run(f, source="snmp", source_ref="snmp:sw1", mac="AA-BB-CC-00-11-22",
            hostname="sw1", ip=["10.77.0.2"], vendor="Acme", ports=[
                {"port": 22, "proto": "tcp", "state": "open"}])
    b = run(f, source="api", source_ref="unifi", mac="aa:bb:cc:00:11:22",
            identifiers={"unifi": "dev-1"}, ip=["10.77.0.3"], model="USW-8",
            observed_at=T0 + timedelta(minutes=1),
            ports=[{"port": 443, "proto": "tcp", "state": "open"}])
    assert a.action == "created" and b.action == "merged"
    assert b.matched_by == "mac" and a.device_id == b.device_id
    [dev] = devices(f)
    assert dev.hostname == "sw1" and dev.model == "USW-8" and dev.vendor == "Acme"
    assert set(dev.ip["v"]) == {"10.77.0.2", "10.77.0.3"}
    assert {p["port"] for p in dev.ports["v"]} == {22, 443}
    assert dev.first_seen == T0 and dev.last_seen == T0 + timedelta(minutes=1)
    got = rows(f, dev.id)
    assert {r.source for r in got} == {"snmp", "api"} and len(got) == 2
    # the vendor id is now bound, so it outranks MAC/IP on the next sighting
    c = run(f, source="api", source_ref="unifi", identifiers={"unifi": "dev-1"},
            ip=["10.77.0.99"], observed_at=T0 + timedelta(minutes=2))
    assert c.matched_by == "identifier" and c.device_id == a.device_id
    assert len(devices(f)) == 1


def test_vendor_identifier_beats_mac_and_conflict_is_recorded(job_session_factory):
    f = job_session_factory
    a = run(f, mac="aa:aa:aa:aa:aa:01", identifiers={"unifi": "u-1"})
    b = run(f, mac="aa:aa:aa:aa:aa:02", identifiers={"unifi": "u-2"})
    assert a.device_id != b.device_id
    r = run(f, identifiers={"unifi": "u-1"}, mac="aa:aa:aa:aa:aa:02",
            observed_at=T0 + timedelta(minutes=1))
    assert r.device_id == a.device_id and r.matched_by == "identifier"
    assert any(c["type"] == "identity_conflict" and c["device_id"] == b.device_id
               for c in r.conflicts)
    assert len(devices(f)) == 2
    with f() as db:  # the contested MAC was not stolen
        owner = db.scalar(select(DeviceIdentity.device_id).where(
            DeviceIdentity.source == "mac", DeviceIdentity.external_id == "aa:aa:aa:aa:aa:02"))
        assert owner == b.device_id
        assert db.get(Device, a.device_id).mac == "aa:aa:aa:aa:aa:01"


def test_dhcp_churn_same_mac_keeps_one_asset(job_session_factory):
    f = job_session_factory
    a = run(f, mac="aa:aa:aa:aa:aa:01", ip=["10.77.0.10"])
    b = run(f, mac="aa:aa:aa:aa:aa:01", ip=["10.77.0.50"],
            observed_at=T0 + timedelta(hours=1))
    assert a.device_id == b.device_id and len(devices(f)) == 1


def test_reused_ip_with_different_mac_does_not_collapse_hosts(job_session_factory):
    f = job_session_factory
    a = run(f, mac="aa:aa:aa:aa:aa:01", hostname="laptop", ip=["10.77.0.10"])
    b = run(f, mac="aa:aa:aa:aa:aa:02", hostname="phone", ip=["10.77.0.10"],
            observed_at=T0 + timedelta(hours=1))
    assert a.device_id != b.device_id and b.action == "created"
    assert any(c["type"] == "ip_held_by_other_device" for c in b.conflicts)
    with job_session_factory() as db:
        assert db.get(Device, a.device_id).mac == "aa:aa:aa:aa:aa:01"
    # now ambiguous: weak IP-only evidence is refused, nothing is written
    with f() as db:
        with pytest.raises(AmbiguousObservation):
            reconcile_observation(db, obs(ip=["10.77.0.10"],
                                          observed_at=T0 + timedelta(hours=2)))
        assert not db.new and not db.dirty


def test_weak_hostname_conflict_is_not_merged(job_session_factory):
    f = job_session_factory
    a = run(f, hostname="nas", ip=["10.77.0.20"])
    b = run(f, hostname="printer", ip=["10.77.0.20"], observed_at=T0 + timedelta(hours=1))
    assert a.device_id != b.device_id


def test_placeholder_hostname_is_upgraded_but_curated_is_kept(job_session_factory):
    f = job_session_factory
    a = run(f, source="scan", ip=["10.77.0.30"])  # placeholder name == IP
    assert devices(f)[0].hostname == "10.77.0.30"
    run(f, hostname="cam-1", ip=["10.77.0.30"], observed_at=T0 + timedelta(minutes=1))
    with f() as db:
        dev = db.get(Device, a.device_id)
        assert dev.hostname == "cam-1"
        dev.hostname = "Front Door Camera"
        dev.location = "porch"
        dev.notes = "do not touch"
        dev.roles = {"v": ["camera"]}
        dev.vendor = "Curated"
        db.commit()
    r = run(f, hostname="Front Door Camera", ip=["10.77.0.30"], vendor="Other",
            observed_at=T0 + timedelta(minutes=2))
    with f() as db:
        dev = db.get(Device, a.device_id)
        assert (dev.hostname, dev.location, dev.notes) == (
            "Front Door Camera", "porch", "do not touch")
        assert dev.roles == {"v": ["camera"]} and dev.vendor == "Curated"
    assert any(c["type"] == "field_conflict" and c["field"] == "vendor" for c in r.conflicts)


def test_stale_observation_does_not_overwrite(job_session_factory):
    f = job_session_factory
    new = run(f, source_ref="s", mac="aa:aa:aa:aa:aa:01", ip=["10.77.0.40"],
              observed_at=T0 + timedelta(hours=2))
    old = run(f, source_ref="s", mac="aa:aa:aa:aa:aa:01", ip=["10.77.0.41"], model="Old",
              observed_at=T0)
    assert old.stale and old.device_id == new.device_id
    [dev] = devices(f)
    assert dev.ip["v"] == ["10.77.0.40"] and dev.model is None
    assert dev.last_seen == T0 + timedelta(hours=2)
    assert dev.first_seen == T0  # history may move earlier
    [row] = rows(f, dev.id)
    assert row.observed_at == T0 + timedelta(hours=2) and "model" not in row.data


def test_repeat_observation_updates_in_place_and_clamps_future(job_session_factory):
    f = job_session_factory
    for n in range(3):
        run(f, source_ref="s", mac="aa:aa:aa:aa:aa:01", observed_at=T0 + timedelta(minutes=n))
    [dev] = devices(f)
    assert len(rows(f, dev.id)) == 1
    future = datetime.now(UTC) + timedelta(days=30)
    run(f, source_ref="s", mac="aa:aa:aa:aa:aa:01", observed_at=future)
    [dev] = devices(f)
    assert dev.last_seen < datetime.now(UTC) + timedelta(minutes=10)


def test_input_validation():
    for bad in (
        {"source": "scan"},  # no evidence
        {"source": "scan", "ip": ["127.0.0.1"]},
        {"source": "scan", "ip": ["0.0.0.0"]},  # noqa: S104
        {"source": "scan", "mac": "nope"},
        {"source": "scan", "ip": ["10.0.0.1"], "identifiers": {"hostname": "x"}},
        {"source": "scan", "ip": ["10.0.0.1"], "data": {"nested": {"password": "x"}}},
        {"source": "bogus", "ip": ["10.0.0.1"]},
    ):
        with pytest.raises(ValidationError):
            ReconcileObservation(**bad)


def test_icmp_results_create_merge_and_skip(job_session_factory):
    f = job_session_factory
    known = run(f, mac="aa:aa:aa:aa:aa:01", hostname="srv", ip=["10.77.0.5"])
    run(f, mac="aa:aa:aa:aa:aa:02", ip=["10.77.0.6"])
    run(f, mac="aa:aa:aa:aa:aa:03", ip=["10.77.0.6"], hostname="x")
    at = (T0 + timedelta(hours=1)).isoformat()
    result = {"probe": "icmp_echo", "hosts": [
        {"ip": "10.77.0.5", "observed_at": at},
        {"ip": "10.77.0.7", "observed_at": at},
        {"ip": "10.77.0.6", "observed_at": at},   # ambiguous
        {"ip": "garbage", "observed_at": at},
        "nope",
    ]}
    with f() as db:
        persist_icmp_scan_result(db, "job-1", result)
        db.commit()
    assert result["asset_reconciliation"] == {
        "created": 1, "merged": 1, "ambiguous": 1, "invalid": 2}
    with f() as db:
        assert db.get(Device, known.device_id).last_seen == T0 + timedelta(hours=1)
    assert len(devices(f)) == 4
    with f() as db:  # non-ICMP results are untouched
        other = {"probe": "tcp_connect"}
        persist_icmp_scan_result(db, "j", other)
        assert "asset_reconciliation" not in other


# -- API -------------------------------------------------------------------


def test_reconcile_endpoint_requires_auth(anon_client):
    r = anon_client.post(f"{API}/reconcile", json={"source": "scan", "ip": ["10.0.0.1"]})
    assert r.status_code in (401, 403)


def test_reconcile_endpoint_provenance_and_ambiguity(client):
    h = client.csrf_headers
    before_ids = {d["id"] for d in client.get(API).json()}
    r1 = client.post(f"{API}/reconcile", headers=h, json={
        "source": "snmp", "source_ref": "snmp:sw", "mac": "AA:BB:CC:DD:EE:01",
        "hostname": "sw", "ip": ["10.0.9.2"], "vendor": "Acme"})
    assert r1.status_code == 200, r1.text
    assert r1.json()["action"] == "created"
    did = r1.json()["device_id"]
    r2 = client.post(f"{API}/reconcile", headers=h, json={
        "source": "api", "source_ref": "unifi", "mac": "aa-bb-cc-dd-ee-01",
        "identifiers": {"unifi": "x1"}})
    assert r2.status_code == 200 and r2.json()["device_id"] == did
    obs_rows = client.get(f"{API}/{did}/observations").json()
    assert {o["source"] for o in obs_rows} == {"snmp", "api"}
    assert all("reconciliation" in o["data"] for o in obs_rows)
    ids = client.get(f"{API}/{did}/identities").json()
    assert {i["source"] for i in ids} == {"mac", "unifi"}
    # Two sources must resolve to exactly one new canonical device.
    # Other tests may already have populated the shared test database.
    after_ids = {d["id"] for d in client.get(API).json()}
    assert after_ids == before_ids | {did}

    client.post(f"{API}/reconcile", headers=h, json={
        "source": "snmp", "mac": "AA:BB:CC:DD:EE:02", "ip": ["10.0.9.2"]})
    amb = client.post(f"{API}/reconcile", headers=h, json={"source": "scan", "ip": ["10.0.9.2"]})
    assert amb.status_code == 409
    bad = client.post(f"{API}/reconcile", headers=h, json={
        "source": "scan", "ip": ["10.0.9.9"], "data": {"token": "x"}})
    assert bad.status_code == 422


@pytest.mark.parametrize(
    "name", ["token", "api_key", "API-KEY", "password", "community", "private_key"]
)
def test_identifier_names_cannot_carry_credential_values(name):
    with pytest.raises(ValidationError):
        ReconcileObservation(
            source="api", identifiers={name: "fictional-value-for-test-only"}
        )


def test_identifier_names_normalized_without_silent_collisions():
    with pytest.raises(ValidationError):
        ReconcileObservation(
            source="api", identifiers={"Unifi": "a", "unifi": "b"}
        )


def test_conflicting_strong_owners_are_quarantined_without_mutating_asset(
    job_session_factory,
):
    f = job_session_factory
    a = run(
        f, source="api", source_ref="owner-a", identifiers={"unifi": "u-a"},
        mac="aa:aa:aa:aa:aa:01", hostname="switch-a", ip=["10.77.0.1"],
    )
    b = run(
        f, source="api", source_ref="owner-b", identifiers={"unifi": "u-b"},
        mac="aa:aa:aa:aa:aa:02", hostname="switch-b", ip=["10.77.0.2"],
    )
    disputed = run(
        f, source="api", source_ref="mixed-evidence", identifiers={"unifi": "u-a"},
        mac="aa:aa:aa:aa:aa:02", ip=["10.77.0.99"], model="WRONG",
        ports=[{"port": 12345, "proto": "tcp", "state": "open"}],
        observed_at=T0 + timedelta(hours=1),
    )
    assert disputed.device_id == a.device_id != b.device_id
    assert disputed.applied_fields == []
    assert any(c["type"] == "identity_conflict" for c in disputed.conflicts)
    with f() as db:
        dev = db.get(Device, a.device_id)
        assert dev.ip["v"] == ["10.77.0.1"]
        assert dev.model is None and dev.ports["v"] == []
        assert dev.last_seen == T0
        evidence = db.get(DeviceObservation, disputed.observation_id)
        assert evidence.data["reconciliation"]["quarantined"] is True
        assert evidence.data["mac"] == "aa:aa:aa:aa:aa:02"


def test_vendor_id_with_unclaimed_conflicting_mac_cannot_update_asset(
    job_session_factory,
):
    f = job_session_factory
    a = run(f, identifiers={"unifi": "u-a"}, mac="aa:aa:aa:aa:aa:01")
    disputed = run(
        f, identifiers={"unifi": "u-a"}, mac="aa:aa:aa:aa:aa:03",
        ip=["10.77.0.99"], observed_at=T0 + timedelta(hours=2),
    )
    assert disputed.device_id == a.device_id and not disputed.applied_fields
    with f() as db:
        dev = db.get(Device, a.device_id)
        assert dev.ip["v"] == [] and dev.last_seen == T0
        assert db.get(DeviceObservation, disputed.observation_id).data[
            "reconciliation"
        ]["quarantined"] is True


def test_mac_match_with_different_vendor_id_is_quarantined(job_session_factory):
    f = job_session_factory
    a = run(f, identifiers={"unifi": "u-a"}, mac="aa:aa:aa:aa:aa:01")
    disputed = run(
        f, mac="aa:aa:aa:aa:aa:01", identifiers={"unifi": "u-new"},
        ip=["10.77.0.99"], observed_at=T0 + timedelta(hours=2),
    )
    assert disputed.device_id == a.device_id and not disputed.applied_fields
    assert any(c["type"] == "identifier_mismatch" for c in disputed.conflicts)
    with f() as db:
        dev = db.get(Device, a.device_id)
        assert dev.ip["v"] == [] and dev.last_seen == T0
        assert db.get(DeviceObservation, disputed.observation_id).data[
            "reconciliation"
        ]["quarantined"] is True
