"""M13 connect-test route: auth, CSRF, scope, credential handling, secrecy."""
from __future__ import annotations

import uuid

import pytest

from app.api.v1.routers.snmp import get_snmp_transport
from app.connectors.base import ConnectorError
from app.connectors.snmp import ALLOWED_OIDS, MISSING
from app.db import SessionLocal
from app.main import app

AUTH = "SNMP-AUTH-MARKER-pass1234"  # noqa: S105 - fixture
PRIV = "SNMP-PRIV-MARKER-pass1234"  # noqa: S105 - fixture


class Fake:
    def __init__(self, values=None, error=None):
        self.values, self.error, self.targets = values or {}, error, []

    async def get(self, target, oids):
        self.targets.append(target)
        if self.error:
            raise self.error
        return {o: self.values.get(o, MISSING) for o in oids}


@pytest.fixture(autouse=True)
def _tables():
    from app.db import Base, engine

    Base.metadata.create_all(bind=engine)
    yield
    app.dependency_overrides.pop(get_snmp_transport, None)
    from app import models

    with SessionLocal() as db:
        db.query(models.ConnectorCredential).delete()
        db.commit()


def use(fake):
    app.dependency_overrides[get_snmp_transport] = lambda: fake
    return fake


def device(client, ip="10.20.30.40"):
    r = client.post("/api/v1/devices", json={"hostname": "sw-" + uuid.uuid4().hex[:6], "ip": [ip]},
                    headers=client.csrf_headers)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def put_creds(client, dev, both=True):
    r = client.put(f"/api/v1/credentials/devices/{dev}/snmpv3_auth", headers=client.csrf_headers,
                   json={"secret": {"password": AUTH},
                         "metadata": {"username": "monitor", "protocol": "SHA256"}})
    assert r.status_code in (200, 201), r.text
    if both:
        r = client.put(f"/api/v1/credentials/devices/{dev}/snmpv3_priv",
                       headers=client.csrf_headers,
                       json={"secret": {"password": PRIV}, "metadata": {"protocol": "AES128"}})
        assert r.status_code in (200, 201), r.text


def test_requires_session(anon_client):
    r = anon_client.post("/api/v1/devices/any/snmp/test", json={})
    assert r.status_code in (401, 403)


def test_requires_csrf(client):
    dev = device(client)
    assert client.post(f"/api/v1/devices/{dev}/snmp/test", json={}).status_code == 403


def test_success_returns_identity_without_secrets(client):
    fake = use(Fake({ALLOWED_OIDS["sys_name"]: b"core",
                     ALLOWED_OIDS["sys_object_id"]: "1.3.6.1.4.1.9"}))
    dev = device(client)
    put_creds(client, dev)
    r = client.post(f"/api/v1/devices/{dev}/snmp/test", json={}, headers=client.csrf_headers)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True and r.json()["result"]["sys_name"] == "core"
    assert r.headers["cache-control"] == "no-store"
    assert "MARKER" not in r.text
    assert fake.targets[0].address == "10.20.30.40" and fake.targets[0].port == 161


def test_connector_failure_is_sanitized(client):
    use(Fake(error=ConnectorError("timeout", "No response from the SNMP agent")))
    dev = device(client)
    put_creds(client, dev)
    r = client.post(f"/api/v1/devices/{dev}/snmp/test", json={}, headers=client.csrf_headers)
    assert r.status_code == 200 and r.json() == {
        "ok": False, "result": None,
        "error": {"code": "timeout", "message": "No response from the SNMP agent"}}


def test_missing_credentials_conflict(client):
    fake = use(Fake())
    dev = device(client)
    r = client.post(f"/api/v1/devices/{dev}/snmp/test", json={}, headers=client.csrf_headers)
    assert r.status_code == 409 and fake.targets == []
    put_creds(client, dev, both=False)  # auth only: authNoPriv is never accepted
    r = client.post(f"/api/v1/devices/{dev}/snmp/test", json={}, headers=client.csrf_headers)
    assert r.status_code == 409 and fake.targets == []


def test_public_address_outside_policy_refused(client):
    fake = use(Fake())
    dev = device(client, ip="8.8.8.8")
    put_creds(client, dev)
    r = client.post(f"/api/v1/devices/{dev}/snmp/test", json={}, headers=client.csrf_headers)
    assert r.status_code == 403 and fake.targets == []


def test_ip_must_belong_to_device_and_be_ipv4(client):
    fake = use(Fake())
    dev = device(client)
    put_creds(client, dev)
    for bad in ("10.20.30.41", "not-an-ip", "10.20.30.0/24"):
        r = client.post(f"/api/v1/devices/{dev}/snmp/test", json={"ip": bad},
                        headers=client.csrf_headers)
        assert r.status_code == 422, bad
    assert fake.targets == []


def test_unknown_device_and_extra_fields(client):
    use(Fake())
    assert client.post("/api/v1/devices/nope/snmp/test", json={},
                       headers=client.csrf_headers).status_code == 404
    dev = device(client)
    assert client.post(f"/api/v1/devices/{dev}/snmp/test", json={"port": 22},
                       headers=client.csrf_headers).status_code == 422


def test_no_ipv4_address(client):
    use(Fake())
    dev = client.post("/api/v1/devices", json={"hostname": "noip"},
                      headers=client.csrf_headers).json()["id"]
    put_creds(client, dev)
    assert client.post(f"/api/v1/devices/{dev}/snmp/test", json={},
                       headers=client.csrf_headers).status_code == 422
