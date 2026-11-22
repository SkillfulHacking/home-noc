"""Key-to-database binding (M04 blocker). Independent of other test modules."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from alembic import command
from app import credentials as svc
from app import crypto, key_binding, models
from app.config import settings
from app.db import Base, SessionLocal, engine

TOKEN = "UNIFI-TOKEN-MARKER-0123456789"  # noqa: S105 - fixture value
TOKEN_2 = "UNIFI-ROTATED-MARKER-9876543210"  # noqa: S105


def _new_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _use(monkeypatch, value: str | None) -> None:
    monkeypatch.setattr(
        settings, "credential_encryption_key", SecretStr(value) if value else None
    )


def _wipe() -> None:
    with SessionLocal() as db:
        db.query(models.ConnectorCredential).delete()
        db.query(models.CredentialKeyVerifier).delete()
        db.commit()


@pytest.fixture(autouse=True)
def _clean():
    Base.metadata.create_all(bind=engine)
    _wipe()
    yield
    _wipe()


def _url(name: str | None = None) -> str:
    return f"/api/v1/credentials/connectors/{name or 'u' + uuid.uuid4().hex[:8]}/unifi_api_token"


def _put(client, url, token=TOKEN):
    return client.put(url, json={"secret": {"token": token}}, headers=client.csrf_headers)


def _rows() -> list[tuple[str, bytes]]:
    with SessionLocal() as db:
        return [(r.id, bytes(r.ciphertext)) for r in db.query(models.ConnectorCredential)]


def _verifier() -> tuple[bytes, bytes] | None:
    with SessionLocal() as db:
        rec = db.query(models.CredentialKeyVerifier).one_or_none()
        return None if rec is None else (bytes(rec.salt), bytes(rec.verifier))


def _drop_verifier() -> None:
    with SessionLocal() as db:
        db.query(models.CredentialKeyVerifier).delete()
        db.commit()


def _assert_sanitized(text: str, *keys: str) -> None:
    assert "MARKER" not in text
    for k in keys:
        assert k not in text
        assert k.rstrip("=") not in text


# ---- verifier construction -----------------------------------------------------


def test_verifier_is_domain_separated_salted_hmac_sha256():
    key = os.urandom(32)
    salt = os.urandom(16)
    got = key_binding.compute_verifier(key, version=1, salt=salt)
    expected = hmac.new(
        key, b"home-noc/credential-key-verifier\x00v1\x00" + salt, hashlib.sha256
    ).digest()
    assert got == expected and len(got) == 32
    assert key_binding.compute_verifier(key, version=1, salt=os.urandom(16)) != got
    assert key_binding.compute_verifier(key, version=2, salt=salt) != got
    assert key not in got
    with pytest.raises(crypto.CredentialKeyError):
        key_binding.compute_verifier(b"short", version=1, salt=salt)


# ---- empty database / first write -----------------------------------------------


def test_empty_database_initializes_verifier_with_first_write(client):
    assert _verifier() is None
    # Read-only status on an empty database never creates a verifier.
    assert client.get(_url()).status_code == 200
    assert _verifier() is None

    assert _put(client, _url()).status_code == 201
    salt, verifier = _verifier()
    key = crypto.load_key()
    assert verifier == key_binding.compute_verifier(key, version=1, salt=salt)
    assert key not in verifier and key not in salt
    assert base64.urlsafe_b64encode(key) not in verifier


def test_failed_first_write_leaves_no_verifier(client):
    resp = client.put(_url(), json={"secret": {"token": "short"}}, headers=client.csrf_headers)
    assert resp.status_code == 422
    assert _verifier() is None and _rows() == []


def test_lost_first_write_race_never_replaces_winner(monkeypatch):
    key_a, key_b = os.urandom(32), os.urandom(32)
    with SessionLocal() as winner:
        key_binding.bind_for_write(winner, key_a)
        winner.commit()
    stored = _verifier()

    real = key_binding._get_record

    def stale_once():
        state = {"n": 0}

        def _stale(db):
            state["n"] += 1
            return None if state["n"] == 1 else real(db)

        return _stale

    # Loser holding key B believed the database was empty: it must be rejected.
    monkeypatch.setattr(key_binding, "_get_record", stale_once())
    with SessionLocal() as loser, pytest.raises(key_binding.CredentialKeyMismatchError):
        key_binding.bind_for_write(loser, key_b)
    assert _verifier() == stored

    # Loser holding the same key A simply proceeds.
    monkeypatch.setattr(key_binding, "_get_record", stale_once())
    with SessionLocal() as loser:
        key_binding.bind_for_write(loser, key_a)
    assert _verifier() == stored


def test_verifier_is_a_singleton():
    with SessionLocal() as db:
        key_binding.bind_for_write(db, os.urandom(32))
        db.commit()
        db.add(
            models.CredentialKeyVerifier(
                id=2, version=1, salt=bytes(16), verifier=bytes(32),
                created_at=datetime.now(UTC),
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()


# ---- same key / restart ----------------------------------------------------------


def test_same_key_works_across_restart(client):
    url = _url()
    assert _put(client, url).status_code == 201
    stored = _verifier()

    # "Restart": startup verification and brand-new sessions see the same key.
    key_binding.verify_at_startup()
    with SessionLocal() as db:
        key_binding.check_usable(db)
        assert svc.reveal(db.query(models.ConnectorCredential).one()) == {"token": TOKEN}

    assert client.get(url).json()["configured"] is True
    assert _put(client, url, TOKEN_2).status_code == 200
    assert _put(client, _url()).status_code == 201
    assert _verifier() == stored


# ---- wrong key -------------------------------------------------------------------


def test_wrong_key_cannot_read_rotate_create_or_delete(client, monkeypatch, caplog):
    key_a = settings.credential_encryption_key.get_secret_value()
    url = _url()
    assert _put(client, url).status_code == 201
    before_rows, before_verifier = _rows(), _verifier()

    key_b = _new_key()
    _use(monkeypatch, key_b)
    with caplog.at_level("DEBUG"):
        responses = [
            client.get(url),
            client.get(url.rsplit("/", 1)[0]),  # connector listing
            _put(client, url, TOKEN_2),  # rotate
            _put(client, _url()),  # create another
            client.delete(url, headers=client.csrf_headers),
        ]
    for resp in responses:
        assert resp.status_code == 503, resp.text
        assert resp.json() == {"detail": "Credential encryption is not available"}
        assert "no-store" in resp.headers["cache-control"]
        _assert_sanitized(resp.text, key_a, key_b)
    _assert_sanitized(caplog.text, key_a, key_b)
    assert _rows() == before_rows and _verifier() == before_verifier

    with SessionLocal() as db, pytest.raises(crypto.CredentialDecryptionError):
        svc.reveal(db.query(models.ConnectorCredential).one())

    # Restoring key A restores access; nothing was damaged.
    _use(monkeypatch, key_a)
    assert client.get(url).json()["configured"] is True
    with SessionLocal() as db:
        assert svc.reveal(db.query(models.ConnectorCredential).one()) == {"token": TOKEN}


def test_status_never_reports_configured_for_wrong_key(client, monkeypatch):
    device = client.post(
        "/api/v1/devices", json={"hostname": "sw-" + uuid.uuid4().hex[:6]},
        headers=client.csrf_headers,
    ).json()["id"]
    assert _put(client, f"/api/v1/credentials/devices/{device}/unifi_api_token").status_code == 201
    _use(monkeypatch, _new_key())
    listing = client.get(f"/api/v1/credentials/devices/{device}")
    single = client.get(f"/api/v1/credentials/devices/{device}/unifi_api_token")
    assert listing.status_code == single.status_code == 503
    assert "configured" not in listing.text and "configured" not in single.text


def test_mismatch_detected_on_restart(monkeypatch, client, caplog):
    assert _put(client, _url()).status_code == 201
    key_b = _new_key()
    _use(monkeypatch, key_b)

    with caplog.at_level("DEBUG"):
        key_binding.verify_at_startup()  # non-production: logged, not fatal
        monkeypatch.setattr(settings, "app_env", "production")
        with pytest.raises(key_binding.CredentialKeyMismatchError) as info:
            key_binding.verify_at_startup()
    assert "does not match" in caplog.text
    _assert_sanitized(caplog.text + str(info.value) + repr(info.value), key_b)


def test_mismatch_survives_deletion_of_all_credentials(client, monkeypatch):
    url = _url()
    assert _put(client, url).status_code == 201
    key_a = settings.credential_encryption_key.get_secret_value()
    stored = _verifier()
    assert client.delete(url, headers=client.csrf_headers).status_code == 204
    assert _rows() == []

    _use(monkeypatch, _new_key())
    assert client.get(url).status_code == 503
    assert _put(client, url).status_code == 503
    assert _rows() == [] and _verifier() == stored  # verifier never replaced

    _use(monkeypatch, key_a)
    assert _put(client, url).status_code == 201


def test_mixed_key_database_creation_is_prevented(client, monkeypatch):
    assert _put(client, _url()).status_code == 201
    _use(monkeypatch, _new_key())
    for _ in range(3):
        assert _put(client, _url()).status_code == 503
    assert len(_rows()) == 1

    # Direct service use (bypassing the HTTP gate) is also refused.
    spec = svc.get_spec("unifi_api_token")
    with SessionLocal() as db:
        with pytest.raises(key_binding.CredentialKeyMismatchError):
            svc.upsert(db, svc.Scope.connector("direct"), spec, {"token": TOKEN}, {})
        db.rollback()
    assert len(_rows()) == 1


# ---- missing / malformed key -----------------------------------------------------


@pytest.mark.parametrize("bad_key", [None, "not-a-valid-key", "AAAA"])
def test_missing_or_malformed_key_fails_closed(client, monkeypatch, bad_key):
    _use(monkeypatch, bad_key)
    url = _url()
    assert client.get(url).status_code == 503
    assert _put(client, url).status_code == 503
    assert client.delete(url, headers=client.csrf_headers).status_code == 503
    assert _rows() == [] and _verifier() is None


def test_inventory_and_auth_work_without_a_key(client, monkeypatch):
    _use(monkeypatch, None)
    assert client.get("/api/v1/devices").status_code == 200
    created = client.post(
        "/api/v1/devices", json={"hostname": "nokey-" + uuid.uuid4().hex[:6]},
        headers=client.csrf_headers,
    )
    assert created.status_code == 200, created.text
    assert client.get(_url()).status_code == 503


# ---- databases that predate the verifier ------------------------------------------


def test_pre_verifier_database_binds_only_after_rows_authenticate(client, monkeypatch):
    key_a = settings.credential_encryption_key.get_secret_value()
    url = _url()
    assert _put(client, url).status_code == 201
    _drop_verifier()  # simulate a database created before the verifier existed
    rows = _rows()

    _use(monkeypatch, _new_key())
    assert client.get(url).status_code == 503  # existing rows fail authentication
    assert _put(client, url, TOKEN_2).status_code == 503
    assert _put(client, _url()).status_code == 503
    assert _verifier() is None and _rows() == rows  # no verifier from a wrong key

    _use(monkeypatch, key_a)
    assert client.get(url).json()["configured"] is True
    assert _verifier() is None  # reads do not establish a binding
    assert _put(client, _url()).status_code == 201
    assert _verifier() is not None

    _use(monkeypatch, _new_key())
    assert _put(client, _url()).status_code == 503


def test_one_undecryptable_legacy_row_blocks_binding(client, monkeypatch):
    assert _put(client, _url()).status_code == 201
    assert _put(client, _url()).status_code == 201
    _drop_verifier()
    with SessionLocal() as db:
        row = db.query(models.ConnectorCredential).first()
        tampered = bytearray(row.ciphertext)
        tampered[-1] ^= 1
        row.ciphertext = bytes(tampered)
        db.commit()
    assert _put(client, _url()).status_code == 503
    assert _verifier() is None


# ---- migration -----------------------------------------------------------------------


def _alembic_config() -> Config:
    backend_root = Path(__file__).resolve().parents[1]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "alembic"))
    return config


def test_verifier_migration_round_trip_and_pre_verifier_adoption(tmp_path):
    url = f"sqlite:///{tmp_path / 'bind.sqlite'}"
    original = settings.db_url
    settings.db_url = url
    config = _alembic_config()
    key_a, key_b = os.urandom(32), os.urandom(32)
    aad = crypto.build_aad(
        credential_id="c1", scope_key="connector:unifi", credential_type="unifi_api_token"
    )
    db_engine = sa.create_engine(url)
    try:
        command.upgrade(config, "0004_connector_credentials")
        with db_engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO connector_credentials (id, scope_key, connector, "
                    "credential_type, enc_version, ciphertext, meta, created_at, updated_at) "
                    "VALUES ('c1', 'connector:unifi', 'unifi', 'unifi_api_token', 1, :ct, "
                    "'{}', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {"ct": crypto.encrypt(b'{"token":"x"}', aad=aad, key=key_a)},
            )

        def creds() -> int:
            with db_engine.connect() as conn:
                return conn.execute(
                    sa.text("SELECT count(*) FROM connector_credentials")
                ).scalar_one()

        command.upgrade(config, "head")
        assert "credential_key_verifier" in sa.inspect(db_engine).get_table_names()
        cols = {c["name"] for c in sa.inspect(db_engine).get_columns("credential_key_verifier")}
        assert cols == {"id", "version", "salt", "verifier", "created_at"}  # no key column
        assert creds() == 1
        with db_engine.connect() as conn:  # the migration itself binds nothing
            assert conn.execute(
                sa.text("SELECT count(*) FROM credential_key_verifier")
            ).scalar_one() == 0

        # Adoption: wrong key refused and writes nothing; right key binds.
        with Session(db_engine) as db:
            with pytest.raises(key_binding.CredentialKeyMismatchError):
                key_binding.bind_for_write(db, key_b)
            db.rollback()
            key_binding.bind_for_write(db, key_a)
            db.commit()
        with Session(db_engine) as db:
            key_binding.check_usable(db, key_a)
            with pytest.raises(key_binding.CredentialKeyMismatchError):
                key_binding.check_usable(db, key_b)

        command.downgrade(config, "0004_connector_credentials")
        assert "credential_key_verifier" not in sa.inspect(db_engine).get_table_names()
        assert creds() == 1
        command.upgrade(config, "head")
        assert "credential_key_verifier" in sa.inspect(db_engine).get_table_names()
        assert creds() == 1
        with Session(db_engine) as db:  # binding is re-established safely
            with pytest.raises(key_binding.CredentialKeyMismatchError):
                key_binding.bind_for_write(db, key_b)
            db.rollback()
            key_binding.bind_for_write(db, key_a)
            db.commit()
    finally:
        db_engine.dispose()
        settings.db_url = original


# ---- leakage ---------------------------------------------------------------------------


def test_no_key_or_verifier_material_in_http_or_logs(client, monkeypatch, caplog):
    key_a = settings.credential_encryption_key.get_secret_value()
    key_b = _new_key()
    texts = []
    with caplog.at_level("DEBUG"):
        url = _url()
        texts.append(_put(client, url).text)
        texts.append(client.get(url).text)
        salt, verifier = _verifier()
        _use(monkeypatch, key_b)
        texts += [client.get(url).text, _put(client, url, TOKEN_2).text]
        key_binding.verify_at_startup()
        texts.append(caplog.text)
    blob = "\n".join(texts)
    _assert_sanitized(blob, key_a, key_b)
    for secret in (salt, verifier):
        assert secret.hex() not in blob
        assert base64.urlsafe_b64encode(secret).decode() not in blob
        assert base64.b64encode(secret).decode() not in blob
    rec = models.CredentialKeyVerifier(
        id=1, version=1, salt=salt, verifier=verifier, created_at=None
    )
    assert verifier.hex() not in repr(rec)
