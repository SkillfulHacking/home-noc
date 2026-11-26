"""M14 routes: auth/CSRF, policy scope, disabled/reconnect state, secrecy."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from app.api.v1.routers.unifi import get_http_factory, normalize_base_url
from app.connectors.base import ConnectorError
from app.connectors.unifi import HttpxUniFiHttp
from app.db import SessionLocal
from app.main import app
from app.models import ConnectorSetting, Device, DeviceIdentity
from tests.test_unifi_connector import FakeHttp, dev

TOKEN = "UNIFI-TOKEN-MARKER-0123456789"  # noqa: S105 - fixture
URL = "https://10.0.0.1"


@pytest.fixture(autouse=True)
def _clean():
    from app import models
    from app.db import Base, engine

    Base.metadata.create_all(bind=engine)
    yield
    app.dependency_overrides.pop(get_http_factory, None)
    with SessionLocal() as db:
        for model in (models.ConnectorCredential, DeviceIdentity, Device, ConnectorSetting):
            db.query(model).delete()
        db.commit()


def use(http):
    seen = {}

    def factory():
        def make(base, token, verify):
            seen.update(base=base, token=token, verify=verify)
            return http
        return make

    app.dependency_overrides[get_http_factory] = factory
    return seen


def token(client):
    r = client.put("/api/v1/credentials/connectors/unifi/unifi_api_token",
                   json={"secret": {"token": TOKEN}}, headers=client.csrf_headers)
    assert r.status_code in (200, 201), r.text


def configure(client, **kw):
    body = {"enabled": True, "base_url": URL, "verify_tls": False, **kw}
    return client.put("/api/v1/connectors/unifi", json=body, headers=client.csrf_headers)


def test_requires_session(anon_client):
    assert anon_client.get("/api/v1/connectors/unifi").status_code in (401, 403)
    assert anon_client.post("/api/v1/connectors/unifi/sync").status_code in (401, 403)


def test_requires_csrf(client):
    assert client.put("/api/v1/connectors/unifi", json={}).status_code == 403
    assert client.post("/api/v1/connectors/unifi/sync").status_code == 403


def test_default_settings_disabled_and_secret_free(client):
    token(client)
    r = client.get("/api/v1/connectors/unifi")
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert r.json()["credential_configured"] is True and "MARKER" not in r.text


@pytest.mark.parametrize("url", ["http://10.0.0.1", "https://unifi.local", "https://u:p@10.0.0.1",
                                 "https://10.0.0.1/path", "https://10.0.0.1?x=1", "ftp://10.0.0.1"])
def test_bad_base_urls_rejected(client, url):
    assert configure(client, base_url=url).status_code == 422


def test_normalize_base_url():
    assert normalize_base_url("https://10.0.0.1:8443/") == ("https://10.0.0.1:8443", "10.0.0.1")


def test_public_controller_outside_policy_rejected(client):
    assert configure(client, base_url="https://8.8.8.8").status_code == 403


def test_enable_requires_url(client):
    assert client.put("/api/v1/connectors/unifi", json={"enabled": True},
                      headers=client.csrf_headers).status_code == 422


def test_sync_imports_and_is_idempotent(client):
    http = FakeHttp(devices=[dev(1), dev(2)])
    seen = use(http)
    token(client)
    assert configure(client).status_code == 200
    r = client.post("/api/v1/connectors/unifi/sync", headers=client.csrf_headers)
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["result"]["devices_created"] == 2 and "MARKER" not in r.text
    assert seen == {"base": URL, "token": TOKEN, "verify": False}
    r2 = client.post("/api/v1/connectors/unifi/sync", headers=client.csrf_headers)
    assert r2.json()["result"]["devices_created"] == 0
    with SessionLocal() as db:
        assert db.query(Device).count() == 2
    state = client.get("/api/v1/connectors/unifi").json()
    assert state["last_status"] == "ok" and state["consecutive_failures"] == 0


def test_disabled_connector_never_contacts_controller(client):
    http = FakeHttp(devices=[dev(1)])
    use(http)
    token(client)
    assert configure(client, enabled=False).status_code == 200
    assert client.post("/api/v1/connectors/unifi/sync",
                       headers=client.csrf_headers).status_code == 409
    assert http.calls == []


def test_failure_then_reconnect_recovers(client):
    http = FakeHttp(devices=[dev(1)], fail=ConnectorError("timeout", "Controller did not respond"))
    use(http)
    token(client)
    configure(client)
    for expected in (1, 2):
        r = client.post("/api/v1/connectors/unifi/sync", headers=client.csrf_headers)
        assert r.status_code == 200 and r.json()["ok"] is False
        assert client.get("/api/v1/connectors/unifi").json()["consecutive_failures"] == expected
    http.fail = None
    assert client.post("/api/v1/connectors/unifi/sync",
                       headers=client.csrf_headers).json()["ok"] is True
    state = client.get("/api/v1/connectors/unifi").json()
    assert state["last_status"] == "ok" and state["consecutive_failures"] == 0
    assert state["credential_configured"] is True  # failures never remove credentials


def test_missing_token_conflict_and_test_route(client):
    http = FakeHttp()
    use(http)
    configure(client)
    assert client.post("/api/v1/connectors/unifi/test",
                       headers=client.csrf_headers).status_code == 409
    token(client)
    r = client.post("/api/v1/connectors/unifi/test", headers=client.csrf_headers)
    assert r.json() == {"ok": True, "result": {"application_version": "9.1.0", "site_count": 1}}


def test_httpx_transport_sends_key_header_and_never_follows_redirects(monkeypatch):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/redir"):
            return httpx.Response(302, headers={"location": "https://evil.example/"})
        return httpx.Response(200, json={"ok": True})

    real = httpx.AsyncClient

    def patched(**kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(**kw)

    monkeypatch.setattr(httpx, "AsyncClient", patched)
    client = HttpxUniFiHttp("https://10.0.0.1", TOKEN, verify_tls=False)
    assert asyncio.run(client.get_json("/x")) == {"ok": True}
    assert requests[0].headers["x-api-key"] == TOKEN and requests[0].method == "GET"
    with pytest.raises(ConnectorError) as exc:
        asyncio.run(client.get_json("/redir"))
    assert exc.value.code == "bad_response" and len(requests) == 2
    assert TOKEN not in repr(client)
