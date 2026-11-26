"""M20 events: one actionable event per change, dedupe, history API."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app import events, health
from app.models import (
    Device,
    DeviceHealth,
    DeviceIdentity,
    DeviceObservation,
    Event,
    HealthSnapshot,
)
from app.reconcile import ReconcileObservation, reconcile_observation

T0 = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def db():
    from app.db import Base, SessionLocal, engine

    Base.metadata.create_all(bind=engine)
    s = SessionLocal()

    def wipe():
        for model in (Event, HealthSnapshot, DeviceHealth, DeviceObservation, DeviceIdentity,
                      Device):
            s.query(model).delete()
        s.commit()

    wipe()
    yield s
    wipe()
    s.close()


def all_events(db, type_=None):
    q = select(Event).order_by(Event.at, Event.id)
    if type_:
        q = q.where(Event.type == type_)
    return list(db.scalars(q))


def obs(**kw):
    base = {"source": "scan", "observed_at": T0, "data": {"probe": "icmp_echo"}}
    return ReconcileObservation(**{**base, **kw})


# ------------------------------------------------------------------- emit ---

def test_emit_dedupes_inside_cooldown_and_reopens_after(db):
    dev = str(uuid.uuid4())
    db.add(Device(id=dev, hostname="a", ip={"v": []}, roles={"v": []}, ports={"v": []}))
    db.commit()
    e1, created1 = events.emit(db, "device_offline", dev, "off", severity="critical", when=T0)
    e2, created2 = events.emit(db, "device_offline", dev, "off", severity="critical",
                               when=T0 + timedelta(minutes=10))
    assert created1 and not created2 and e1.id == e2.id and e1.count == 2
    assert e1.last_at == T0 + timedelta(minutes=10) and e1.hostname == "a"
    _, created3 = events.emit(db, "device_offline", dev, "off", severity="critical",
                              when=T0 + timedelta(hours=2))
    assert created3 and len(all_events(db)) == 2


def test_emit_rejects_unknown_type_or_severity(db):
    with pytest.raises(ValueError):
        events.emit(db, "bogus", None, "x")
    with pytest.raises(ValueError):
        events.emit(db, "device_offline", None, "x", severity="loud")


def test_summary_is_bounded(db):
    e, _ = events.emit(db, "device_offline", None, "x" * 1000)
    assert len(e.summary) == 255


# -------------------------------------------------------------- reconcile ---

def test_new_device_creates_exactly_one_event_and_rescans_do_not(db):
    first = reconcile_observation(db, obs(ip=["10.0.0.5"]))
    db.commit()
    for i in range(3):
        reconcile_observation(db, obs(ip=["10.0.0.5"], observed_at=T0 + timedelta(minutes=i + 1)))
    db.commit()
    found = all_events(db, "device_discovered")
    assert len(found) == 1 and found[0].device_id == first.device_id
    assert found[0].summary.startswith("New device discovered")
    assert all_events(db, "address_changed") == []


def test_new_address_event_once_per_value(db):
    r = reconcile_observation(db, obs(ip=["10.0.0.5"], mac="aa:bb:cc:00:00:01"))
    for ip in ("10.0.0.6", "10.0.0.6", "10.0.0.5", "10.0.0.6"):
        reconcile_observation(db, obs(ip=[ip], mac="aa:bb:cc:00:00:01"))
    db.commit()
    changed = all_events(db, "address_changed")
    assert [e.details["ip"] for e in changed] == ["10.0.0.6"]
    assert changed[0].device_id == r.device_id


def test_new_open_port_event_from_reconcile_and_tcp_scan(db):
    from app.port_observations import persist_tcp_scan_result
    from app.schemas import Port

    r = reconcile_observation(db, obs(ip=["10.0.0.7"]))
    reconcile_observation(db, obs(ip=["10.0.0.7"], ports=[Port(port=22, proto="tcp")]))
    now = datetime.now(UTC).isoformat()
    result = {"probe": "tcp_connect", "finished_at": now, "observations": [
        {"host": "10.0.0.7", "port": 443, "protocol": "tcp", "state": "open", "observed_at": now},
        {"host": "10.0.0.7", "port": 80, "protocol": "tcp", "state": "refused",
         "observed_at": now}]}
    persist_tcp_scan_result(db, "job-1", result)
    persist_tcp_scan_result(db, "job-2", dict(result))  # rescan: nothing new
    db.commit()
    ports = sorted(e.details["port"] for e in all_events(db, "port_opened"))
    assert ports == [22, 443]  # refused port 80 produces no event
    assert all(e.device_id == r.device_id and e.severity == "warning"
               for e in all_events(db, "port_opened"))


# ----------------------------------------------------------------- health ---

def test_offline_transition_one_event_flapping_folds_into_count(db):
    did = str(uuid.uuid4())
    db.add(Device(id=did, hostname="sw", ip={"v": ["10.0.0.9"]}, roles={"v": []},
                  ports={"v": []}))
    db.commit()
    health.record(db, did, "snmp", True, T0)
    t = T0 + timedelta(hours=1)
    for i in range(health.CONFIRM_FAILURES + 2):  # extra failures: still one transition
        health.record(db, did, "snmp", False, t + timedelta(seconds=i))
    assert len(all_events(db, "device_offline")) == 1
    health.record(db, did, "snmp", True, t + timedelta(minutes=5))
    assert len(all_events(db, "device_recovered")) == 1
    for i in range(health.CONFIRM_FAILURES):  # flaps offline again within the cooldown
        health.record(db, did, "snmp", False, t + timedelta(minutes=6, seconds=i))
    off = all_events(db, "device_offline")
    assert len(off) == 1 and off[0].count == 2 and off[0].severity == "critical"


def test_aging_to_unknown_and_first_online_are_silent(db):
    did = str(uuid.uuid4())
    db.add(Device(id=did, hostname="x", ip={"v": []}, roles={"v": []}, ports={"v": []}))
    db.commit()
    health.record(db, did, "icmp", True, T0)
    health.sweep(db, T0 + timedelta(days=1))
    assert all_events(db) == []


# ------------------------------------------------------------------ unifi ---

def test_managed_device_missing_event_once(db):
    from app.connectors.unifi import parse_device
    from app.connectors.unifi_sync import import_snapshot

    row = parse_device({"id": "u1", "macAddress": "aa:bb:cc:00:00:09", "ipAddress": "10.0.0.20",
                        "name": "usw", "state": "ONLINE"})
    snap = {"site": "s", "skipped": 0, "devices": [row], "clients": []}
    import_snapshot(db, snap, T0)
    gone = {"site": "s", "skipped": 0, "devices": [], "clients": []}
    first = import_snapshot(db, gone, T0 + timedelta(hours=1))
    import_snapshot(db, gone, T0 + timedelta(hours=2))
    db.commit()
    assert first["devices_missing"] == 1
    missing = all_events(db, "managed_device_missing")
    assert len(missing) == 1 and missing[0].count == 2


def test_prune_by_age_and_cap(db, monkeypatch):
    for i in range(5):
        events.emit(db, "device_offline", None, f"e{i}", dedupe_key=f"k{i}", when=T0 - timedelta(
            days=100 if i < 2 else 1))
    assert events.prune(db, T0) == 2
    monkeypatch.setattr(events, "MAX_EVENTS", 1)
    assert events.prune(db, T0) == 2 and len(all_events(db)) == 1


# -------------------------------------------------------------------- API ---

URL = "/api/v1/events"


def seed(db, n=5):
    ids = []
    for i in range(n):
        e, _ = events.emit(db, "port_opened" if i % 2 else "device_offline", None,
                           f"event number {i} on host-{i}",
                           severity="warning" if i % 2 else "critical", dedupe_key=f"k{i}",
                           when=T0 + timedelta(minutes=i))
        ids.append(e.id)
    db.commit()
    return ids


def test_events_api_requires_session(anon_client):
    assert anon_client.get(URL).status_code in (401, 403)


def test_events_api_paginates_filters_searches(client, db):
    ids = seed(db)
    first = client.get(URL + "?limit=2").json()
    assert first["total"] == 5 and [e["id"] for e in first["events"]] == [ids[4], ids[3]]
    second = client.get(URL + f"?limit=2&cursor={first['next_cursor']}").json()
    assert [e["id"] for e in second["events"]] == [ids[2], ids[1]]
    last = client.get(URL + f"?limit=2&cursor={second['next_cursor']}").json()
    assert [e["id"] for e in last["events"]] == [ids[0]] and last["next_cursor"] is None
    assert client.get(URL + "?type=port_opened").json()["total"] == 2
    assert client.get(URL + "?severity=critical").json()["total"] == 3
    assert client.get(URL + "?q=host-3").json()["total"] == 1
    assert client.get(URL + "?q=%25").json()["total"] == 0  # wildcard is escaped
    since = (T0 + timedelta(minutes=3)).isoformat().replace("+00:00", "Z")
    assert client.get(URL, params={"since": since}).json()["total"] == 2
    assert client.get(URL + "?cursor=garbage").status_code == 422
    assert client.get(URL + "?type=bogus").status_code == 422
    assert client.get(URL + "?limit=0").status_code == 422


def test_events_api_detail_and_ack(client, db):
    eid = seed(db, 1)[0]
    assert client.get(f"{URL}/{eid}").json()["acknowledged_at"] is None
    assert client.post(f"{URL}/{eid}/ack").status_code == 403  # CSRF required
    acked = client.post(f"{URL}/{eid}/ack", headers=client.csrf_headers).json()
    assert acked["acknowledged_at"]
    assert client.get(URL + "?acknowledged=false").json()["total"] == 0
    assert client.get(URL + "?acknowledged=true").json()["total"] == 1
    assert client.get(f"{URL}/nope").status_code == 404


# ---------------------------------------------------- Gitar-reported regressions ---

def test_repeat_after_acknowledgement_is_a_new_visible_event(db):
    first, _ = events.emit(db, "device_offline", None, "off", severity="critical", when=T0)
    first.acknowledged_at = T0 + timedelta(minutes=1)
    again, created = events.emit(db, "device_offline", None, "off", severity="critical",
                                 when=T0 + timedelta(minutes=10))
    assert created and again.id != first.id and again.acknowledged_at is None


def test_once_events_never_recur_even_when_acknowledged(db):
    first, _ = events.emit(db, "device_discovered", None, "new", dedupe_key="k",
                           cooldown=events.ONCE, when=T0)
    first.acknowledged_at = T0
    _, created = events.emit(db, "device_discovered", None, "new", dedupe_key="k",
                             cooldown=events.ONCE, when=T0 + timedelta(days=5))
    assert not created


def test_folded_repeat_moves_to_the_top_and_matches_since_filter(client, db):
    old, _ = events.emit(db, "device_offline", None, "outage", severity="critical", when=T0)
    events.emit(db, "device_recovered", None, "back", when=T0 + timedelta(minutes=5))
    events.emit(db, "device_offline", None, "outage", severity="critical",
                when=T0 + timedelta(minutes=6))  # folds into `old`
    db.commit()
    body = client.get(URL).json()
    assert [e["id"] for e in body["events"]][0] == old.id and body["events"][0]["count"] == 2
    since = (T0 + timedelta(minutes=5, seconds=30)).isoformat().replace("+00:00", "Z")
    assert [e["id"] for e in client.get(URL, params={"since": since}).json()["events"]] == [old.id]


def _unifi_row(i="u1"):
    from app.connectors.unifi import parse_device

    return parse_device({"id": i, "macAddress": "aa:bb:cc:00:00:09", "ipAddress": "10.0.0.20",
                         "name": "usw", "state": "ONLINE"})


def snap(devices, site="s", skipped_devices=0):
    return {"site": site, "skipped": skipped_devices, "skipped_devices": skipped_devices,
            "devices": devices, "clients": []}


def test_incomplete_device_list_never_reports_missing(db):
    from app.connectors.unifi_sync import import_snapshot

    import_snapshot(db, snap([_unifi_row()]), T0)
    out = import_snapshot(db, snap([], skipped_devices=1), T0 + timedelta(hours=1))
    assert out["devices_missing"] == 0 and all_events(db, "managed_device_missing") == []


def test_switching_site_does_not_report_old_site_devices_missing(db):
    from app.connectors.unifi_sync import import_snapshot

    import_snapshot(db, snap([_unifi_row()], site="site-a"), T0)
    out = import_snapshot(db, snap([], site="site-b"), T0 + timedelta(hours=1))
    assert out["devices_missing"] == 0
    out = import_snapshot(db, snap([], site="site-a"), T0 + timedelta(hours=2))
    assert out["devices_missing"] == 1
