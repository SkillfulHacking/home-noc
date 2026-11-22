from __future__ import annotations

import os
import uuid

import pytest
from pydantic import SecretStr

from app import credentials as svc
from app import crypto, models
from app.config import settings
from app.db import SessionLocal

TOKEN = "UNIFI-TOKEN-MARKER-0123456789"  # noqa: S105 - fixture value
TOKEN_2 = "UNIFI-ROTATED-MARKER-9876543210"  # noqa: S105
AUTH_PW = "SNMP-AUTH-MARKER-pass1234"  # noqa: S105
PRIV_PW = "SNMP-PRIV-MARKER-pass1234"  # noqa: S105
MARKERS = ("MARKER",)


@pytest.fixture(autouse=True)
def _clean_credentials():
    def wipe():
        db = SessionLocal()
        try:
            db.query(models.ConnectorCredential).delete()
            db.commit()
        finally:
            db.close()

    # Ensure this test module works independently of test execution order.
    from app.db import Base, engine

    Base.metadata.create_all(bind=engine)

    wipe()
    yield
    wipe()


def _connector() -> str:
    return "unifi-" + uuid.uuid4().hex[:8]


def _device(client) -> str:
    resp = client.post(
        "/api/v1/devices", json={"hostname": "sw-" + uuid.uuid4().hex[:6]},
        headers=client.csrf_headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _put(client, url, secret, metadata=None, headers=True):
    body = {"secret": secret}
    if metadata is not None:
        body["metadata"] = metadata
    return client.put(url, json=body, headers=client.csrf_headers if headers else {})


def _rows():
    db = SessionLocal()
    try:
        return db.query(models.ConnectorCredential).all()
    finally:
        db.close()


def _assert_no_secret(text: str):
    for marker in MARKERS:
        assert marker not in text
    assert "ciphertext" not in text.lower()


# ---- authentication / CSRF ----------------------------------------------------


def test_anonymous_access_is_rejected(anon_client):
    url = f"/api/v1/credentials/connectors/{_connector()}/unifi_api_token"
    assert anon_client.get(url).status_code == 401
    assert anon_client.get("/api/v1/credentials/connectors/unifi").status_code == 401
    assert anon_client.put(url, json={"secret": {"token": TOKEN}}).status_code == 401
    assert anon_client.delete(url).status_code == 401


def test_mutations_require_csrf(client):
    name = _connector()
    url = f"/api/v1/credentials/connectors/{name}/unifi_api_token"
    resp = client.put(url, json={"secret": {"token": TOKEN}})
    assert resp.status_code == 403
    assert client.put(
        url, json={"secret": {"token": TOKEN}}, headers={"X-CSRF-Token": "wrong"}
    ).status_code == 403
    assert _rows() == []

    assert _put(client, url, {"token": TOKEN}).status_code == 201
    assert client.delete(url).status_code == 403
    assert len(_rows()) == 1
    assert client.delete(url, headers=client.csrf_headers).status_code == 204


# ---- create / replace / delete -------------------------------------------------


def test_unifi_token_lifecycle_and_rotation_revokes_old_value(client):
    name = _connector()
    url = f"/api/v1/credentials/connectors/{name}/unifi_api_token"

    state = client.get(url).json()
    assert state["configured"] is False and state["masked"] is None

    created = _put(client, url, {"token": TOKEN}, {"label": "controller"})
    assert created.status_code == 201
    body = created.json()
    assert body["configured"] is True
    assert body["masked"] == "********"
    assert body["connector"] == name and body["device_id"] is None
    assert body["metadata"] == {"label": "controller"}
    _assert_no_secret(created.text)
    assert "no-store" in created.headers["cache-control"]

    first = _rows()
    assert len(first) == 1
    old_blob = first[0].ciphertext
    assert TOKEN.encode() not in old_blob
    assert svc.reveal(first[0]) == {"token": TOKEN}

    rotated = _put(client, url, {"token": TOKEN_2})
    assert rotated.status_code == 200
    assert rotated.json()["rotated_at"] is not None
    _assert_no_secret(rotated.text)

    after = _rows()
    assert len(after) == 1 and after[0].id == first[0].id
    assert after[0].ciphertext != old_blob  # old ciphertext is gone, not retained
    assert svc.reveal(after[0]) == {"token": TOKEN_2}

    assert client.get(url).json()["configured"] is True
    assert client.delete(url, headers=client.csrf_headers).status_code == 204
    assert _rows() == []
    assert client.get(url).json()["configured"] is False
    # Deletion is idempotent.
    assert client.delete(url, headers=client.csrf_headers).status_code == 204


def test_snmpv3_auth_and_priv_on_device(client):
    device_id = _device(client)
    base = f"/api/v1/credentials/devices/{device_id}"

    auth = _put(client, f"{base}/snmpv3_auth", {"password": AUTH_PW},
                {"username": "monitor", "protocol": "SHA256"})
    priv = _put(client, f"{base}/snmpv3_priv", {"password": PRIV_PW}, {"protocol": "AES256"})
    assert auth.status_code == priv.status_code == 201
    assert auth.json()["metadata"] == {"username": "monitor", "protocol": "SHA256"}
    _assert_no_secret(auth.text + priv.text)

    listing = client.get(base)
    assert listing.status_code == 200
    _assert_no_secret(listing.text)
    states = {c["credential_type"]: c["configured"] for c in listing.json()["credentials"]}
    assert states == {"unifi_api_token": False, "snmpv3_auth": True, "snmpv3_priv": True}

    by_type = {r.credential_type: r for r in _rows()}
    assert svc.reveal(by_type["snmpv3_auth"]) == {"password": AUTH_PW}
    assert svc.reveal(by_type["snmpv3_priv"]) == {"password": PRIV_PW}


def test_deleting_device_removes_its_credentials(client):
    device_id = _device(client)
    url = f"/api/v1/credentials/devices/{device_id}/snmpv3_auth"
    assert _put(client, url, {"password": AUTH_PW}, {"username": "m"}).status_code == 201
    assert len(_rows()) == 1
    resp = client.delete(f"/api/v1/devices/{device_id}", headers=client.csrf_headers)
    assert resp.status_code == 204
    assert _rows() == []


# ---- redaction / separation ----------------------------------------------------


def test_inventory_and_observations_never_contain_credentials(client):
    device_id = _device(client)
    base = f"/api/v1/credentials/devices/{device_id}"
    assert _put(client, f"{base}/snmpv3_auth", {"password": AUTH_PW},
                {"username": "monitor"}).status_code == 201
    assert _put(client, f"{base}/unifi_api_token", {"token": TOKEN}).status_code == 201

    detail = client.get(f"/api/v1/devices/{device_id}")
    listing = client.get("/api/v1/devices")
    observations = client.get(f"/api/v1/devices/{device_id}/observations")
    identities = client.get(f"/api/v1/devices/{device_id}/identities")
    for resp in (detail, listing, observations, identities):
        assert resp.status_code == 200
        _assert_no_secret(resp.text)

    device = detail.json()
    assert device["snmp"] is None and device["api"] is None and device["notes"] is None
    assert observations.json() == []

    # Credential-shaped data is still refused by the inventory surfaces.
    assert client.patch(
        f"/api/v1/devices/{device_id}",
        json={"snmp": {"enabled": True, "password": AUTH_PW}},
        headers=client.csrf_headers,
    ).status_code == 422
    assert client.post(
        f"/api/v1/devices/{device_id}/observations",
        json={"source": "snmp", "data": {"auth_password": AUTH_PW}},
        headers=client.csrf_headers,
    ).status_code == 422


def test_status_model_has_no_secret_bearing_fields():
    from app.credential_schemas import CredentialStatus

    fields = set(CredentialStatus.model_fields)
    assert not {"secret", "token", "password", "ciphertext", "value"} & fields


def test_secret_models_do_not_render_values():
    from app.credential_schemas import UniFiTokenSecret

    model = UniFiTokenSecret(token=TOKEN)
    assert "MARKER" not in repr(model) and "MARKER" not in str(model)
    assert "MARKER" not in model.model_dump_json()
    assert "MARKER" not in str(model.model_dump())


def test_database_holds_only_ciphertext_and_metadata(client):
    url = f"/api/v1/credentials/connectors/{_connector()}/unifi_api_token"
    assert _put(client, url, {"token": TOKEN}, {"label": "x"}).status_code == 201
    row = _rows()[0]
    assert TOKEN.encode() not in row.ciphertext
    assert TOKEN not in str(row.meta) and TOKEN not in repr(row)
    assert row.enc_version == crypto.FORMAT_VERSION
    key = settings.credential_encryption_key.get_secret_value()
    assert key.encode() not in row.ciphertext


# ---- validation, scoping, errors ---------------------------------------------


def test_validation_errors_never_echo_secret_values(client):
    url = f"/api/v1/credentials/connectors/{_connector()}/unifi_api_token"
    cases = [
        {"secret": {"token": "LEAK-MARKER"[:7]}},                      # too short
        {"secret": {"token": TOKEN, "extra": "LEAK-MARKER-EXTRA"}},   # unknown field
        {"secret": {"token": TOKEN + "\n"}},                           # control char
        {"secret": {"nottoken": "LEAK-MARKER-WRONGNAME"}},
        {"secret_typo": "LEAK-MARKER-TOP"},
        {"secret": {"token": TOKEN}, "metadata": {"label": "LEAK-MARKER-META!!"}},
        {"secret": {"token": TOKEN}, "unexpected": TOKEN_2},
    ]
    for payload in cases:
        resp = client.put(url, json=payload, headers=client.csrf_headers)
        assert resp.status_code == 422, payload
        assert "MARKER" not in resp.text
        assert "LEAK" not in resp.text
        assert '"input"' not in resp.text
    assert _rows() == []


def test_snmp_metadata_validation(client):
    device_id = _device(client)
    url = f"/api/v1/credentials/devices/{device_id}/snmpv3_auth"
    assert _put(client, url, {"password": AUTH_PW}, {"protocol": "SHA"}).status_code == 422
    assert _put(client, url, {"password": AUTH_PW},
                {"username": "u", "protocol": "MD5"}).status_code == 422
    assert _put(client, url, {"password": "short"}, {"username": "u"}).status_code == 422
    assert _rows() == []


def test_unknown_resources_are_404(client):
    name = _connector()
    assert client.get(f"/api/v1/credentials/connectors/{name}/nope").status_code == 404
    # snmpv3 credentials belong to devices, not connectors
    assert _put(client, f"/api/v1/credentials/connectors/{name}/snmpv3_auth",
                {"password": AUTH_PW}, {"username": "u"}).status_code == 404
    missing = str(uuid.uuid4())
    assert client.get(f"/api/v1/credentials/devices/{missing}").status_code == 404
    assert _put(client, f"/api/v1/credentials/devices/{missing}/unifi_api_token",
                {"token": TOKEN}).status_code == 404
    assert client.get("/api/v1/credentials/connectors/Bad Name").status_code == 422
    assert _rows() == []


# ---- fail-closed key handling --------------------------------------------------


@pytest.mark.parametrize("bad_key", [None, "not-a-valid-key", "AAAA"])
def test_bad_key_fails_closed_without_writing(client, monkeypatch, caplog, bad_key):
    monkeypatch.setattr(
        settings, "credential_encryption_key", SecretStr(bad_key) if bad_key else None
    )
    url = f"/api/v1/credentials/connectors/{_connector()}/unifi_api_token"
    with caplog.at_level("DEBUG"):
        resp = _put(client, url, {"token": TOKEN})
    assert resp.status_code == 503
    _assert_no_secret(resp.text)
    assert "MARKER" not in caplog.text
    assert _rows() == []  # never a plaintext fallback


def test_wrong_key_and_substitution_cannot_decrypt(client, monkeypatch):
    dev_a, dev_b = _device(client), _device(client)
    for dev in (dev_a, dev_b):
        assert _put(client, f"/api/v1/credentials/devices/{dev}/snmpv3_auth",
                    {"password": AUTH_PW}, {"username": "m"}).status_code == 201
    db = SessionLocal()
    try:
        row_a = db.query(models.ConnectorCredential).filter_by(device_id=dev_a).one()
        row_b = db.query(models.ConnectorCredential).filter_by(device_id=dev_b).one()
        assert svc.reveal(row_a) == {"password": AUTH_PW}

        # Ciphertext substitution between two credentials is detected.
        row_b.ciphertext = row_a.ciphertext
        with pytest.raises(crypto.CredentialDecryptionError):
            svc.reveal(row_b)
        db.rollback()

        # Tampered stored ciphertext is rejected.
        tampered = bytearray(row_a.ciphertext)
        tampered[-1] ^= 0x01
        row_a.ciphertext = bytes(tampered)
        with pytest.raises(crypto.CredentialDecryptionError):
            svc.reveal(row_a)
        db.rollback()

        # A different key cannot read existing rows.
        import base64

        other = base64.urlsafe_b64encode(os.urandom(32)).decode()
        monkeypatch.setattr(settings, "credential_encryption_key", SecretStr(other))
        with pytest.raises(crypto.CredentialDecryptionError) as info:
            svc.reveal(row_a)
        assert "MARKER" not in str(info.value)
    finally:
        db.close()


def test_logs_do_not_contain_credentials(client, caplog):
    name = _connector()
    url = f"/api/v1/credentials/connectors/{name}/unifi_api_token"
    with caplog.at_level("DEBUG"):
        _put(client, url, {"token": TOKEN})
        _put(client, url, {"token": TOKEN_2})
        _put(client, url, {"token": "bad", "extra": TOKEN})
        client.get(url)
        client.delete(url, headers=client.csrf_headers)
    assert "MARKER" not in caplog.text
