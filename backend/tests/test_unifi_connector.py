"""M14 UniFi connector: mocked controller paging/failures, parsing, import, dedupe."""
from __future__ import annotations

import asyncio

import pytest

from app.connectors import registry
from app.connectors.base import ConnectorError
from app.connectors.unifi import API_PREFIX, PAGE_SIZE, UniFiConnector, _decode, parse_device
from app.connectors.unifi_sync import import_snapshot, record_outcome
from app.db import SessionLocal
from app.models import ConnectorSetting, Device, DeviceIdentity

SITE = "site-1"


class FakeHttp:
    """Serves collections page by page and records every request (all GETs)."""

    def __init__(self, devices=(), clients=(), sites=None, fail=None, info=None):
        self.devices, self.clients = list(devices), list(clients)
        self.sites = sites if sites is not None else [{"id": SITE, "name": "Default",
                                                      "internalReference": "default"}]
        self.fail, self.info, self.calls = fail, info or {"applicationVersion": "9.1.0"}, []

    async def get_json(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        if self.fail:
            raise self.fail
        if path.endswith("/info"):
            return self.info
        rows = (self.sites if path.endswith("/sites") else
                self.devices if path.endswith("/devices") else self.clients)
        off, lim = params["offset"], params["limit"]
        return {"offset": off, "limit": lim, "count": len(rows[off:off + lim]),
                "totalCount": len(rows), "data": rows[off:off + lim]}


def dev(i, **kw):
    return {"id": f"d{i}", "macAddress": f"aa:bb:cc:00:00:{i:02x}", "ipAddress": f"10.0.0.{i}",
            "name": f"sw{i}", "model": "USW-24", "state": "ONLINE", "firmwareVersion": "7.0",
            "features": ["switching"], **kw}


def run(c):
    return asyncio.run(c)


def test_registered_and_test_connection():
    assert "unifi" in registry()
    out = run(UniFiConnector(FakeHttp(devices=[dev(1)])).test_connection())
    assert out == {"application_version": "9.1.0", "site_count": 1}


def test_pagination_collects_all_pages_and_only_gets():
    n = PAGE_SIZE * 2 + 7
    http = FakeHttp(devices=[dev(i % 200 + 1, id=f"d{i}") for i in range(n)])
    snap = run(UniFiConnector(http).collect_identity())
    assert len(snap["devices"]) == n
    dev_calls = [p for p in http.calls if p[0].endswith("/devices")]
    assert [c[1]["offset"] for c in dev_calls] == [0, PAGE_SIZE, PAGE_SIZE * 2]
    assert all(path.startswith(API_PREFIX) for path, _ in http.calls)


def test_runaway_paging_is_bounded():
    class Endless(FakeHttp):
        async def get_json(self, path, params=None):
            if path.endswith("/sites"):
                return await super().get_json(path, params)
            return {"data": [dev(1)], "totalCount": 10**9}

    with pytest.raises(ConnectorError) as exc:
        run(UniFiConnector(Endless()).collect_identity())
    assert exc.value.code == "bad_response"


def test_malformed_rows_skipped_and_counted():
    rows = [dev(1), {"id": "x"}, "junk", dev(2, macAddress="bad", ipAddress="nope"),
            dev(3, id="bad id!")]
    snap = run(UniFiConnector(FakeHttp(devices=rows)).collect_identity())
    assert [d["id"] for d in snap["devices"]] == ["d1"]
    assert snap["skipped"] == 4


def test_parse_device_roles_and_ipv6_ignored():
    d = parse_device(dev(5, features=["accessPoint"], ipAddress="fe80::1"))
    assert d["role_hint"] == "access_point" and d["ip"] is None and d["mac"] == "aa:bb:cc:00:00:05"


def test_site_resolution():
    two = [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]
    with pytest.raises(ConnectorError) as exc:
        run(UniFiConnector(FakeHttp(sites=two)).collect_identity())
    assert exc.value.code == "site_required"
    assert run(UniFiConnector(FakeHttp(sites=two)).collect_identity("B"))["site"] == "b"
    with pytest.raises(ConnectorError) as exc:
        run(UniFiConnector(FakeHttp(sites=two)).collect_identity("Z"))
    assert exc.value.code == "site_not_found"


@pytest.mark.parametrize("status,code", [(401, "unauthorized"), (403, "forbidden"),
                                         (404, "not_found"), (302, "bad_response"),
                                         (500, "server_error")])
def test_http_status_mapping(status, code):
    with pytest.raises(ConnectorError) as exc:
        _decode(status, b"{}")
    assert exc.value.code == code


def test_bad_bodies():
    for body in (b"not json", b"x" * (5 * 1024 * 1024 + 1)):
        with pytest.raises(ConnectorError):
            _decode(200, body)
    with pytest.raises(ConnectorError):
        asyncio.run(UniFiConnector(_Bad()).collect_identity())


class _Bad(FakeHttp):
    async def get_json(self, path, params=None):
        return {"unexpected": True}


@pytest.fixture
def db():
    from app.db import Base, engine

    Base.metadata.create_all(bind=engine)
    s = SessionLocal()
    s.query(DeviceIdentity).delete()
    s.query(Device).delete()
    s.commit()
    yield s
    s.query(DeviceIdentity).delete()
    s.query(Device).delete()
    s.query(ConnectorSetting).delete()
    s.commit()
    s.close()


def snapshot(devices=(), clients=()):
    return {"site": SITE, "skipped": 0, "devices": list(map(parse_device, devices)),
            "clients": clients}


def test_import_creates_and_resync_does_not_duplicate(db):
    snap = snapshot([dev(1), dev(2)])
    first = import_snapshot(db, snap)
    db.commit()
    again = import_snapshot(db, snap)
    db.commit()
    assert first["devices_created"] == 2 and again["devices_created"] == 0
    assert again["devices_merged"] == 2 and db.query(Device).count() == 2
    d = db.query(Device).filter_by(mac="aa:bb:cc:00:00:01").one()
    assert d.vendor == "Ubiquiti" and d.model == "USW-24" and d.hostname == "sw1"


def test_import_merges_into_existing_icmp_asset_by_ip(db):
    db.add(Device(id="pre", hostname="10.0.0.1", ip={"v": ["10.0.0.1"]}, roles={"v": []},
                  ports={"v": []}))
    db.commit()
    import_snapshot(db, snapshot([dev(1)]))
    db.commit()
    assert db.query(Device).count() == 1
    d = db.get(Device, "pre")
    assert d.mac == "aa:bb:cc:00:00:01" and d.hostname == "sw1"


def test_import_does_not_overwrite_curated_fields(db):
    db.add(Device(id="cur", hostname="my-core", mac="aa:bb:cc:00:00:01", model="Custom",
                  ip={"v": []}, roles={"v": ["core"]}, ports={"v": []}))
    db.commit()
    import_snapshot(db, snapshot([dev(1)]))
    db.commit()
    d = db.get(Device, "cur")
    assert d.hostname == "my-core" and d.model == "Custom" and d.roles == {"v": ["core"]}


def test_clients_imported_by_mac(db):
    clients = [{"id": "c1", "mac": "11:22:33:44:55:66", "ip": "10.0.0.50",
                "name": "laptop", "kind": "WIRELESS"}]
    out = import_snapshot(db, snapshot([dev(1)], clients))
    db.commit()
    assert out["clients_created"] == 1 and db.query(Device).count() == 2


def test_health_state_transitions():
    row = ConnectorSetting(name="unifi", enabled=True, verify_tls=True, consecutive_failures=0)
    record_outcome(row, ok=False, error_code="timeout")
    record_outcome(row, ok=False, error_code="timeout")
    assert row.last_status == "error" and row.consecutive_failures == 2
    record_outcome(row, ok=True, summary={"devices_created": 1})
    assert row.last_status == "ok" and row.consecutive_failures == 0
    assert row.last_error_code is None and row.last_success_at is not None
