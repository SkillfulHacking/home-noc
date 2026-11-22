from __future__ import annotations

import base64
import os

import pytest
from pydantic import SecretStr

from app import crypto
from app.config import settings

AAD = crypto.build_aad(
    credential_id="cred-1", scope_key="device:d1", credential_type="snmpv3_auth"
)
PLAINTEXT = b'{"password":"ROUNDTRIP-MARKER-1"}'


def _key() -> bytes:
    return os.urandom(32)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def test_round_trip_with_configured_key():
    envelope = crypto.encrypt(PLAINTEXT, aad=AAD)
    assert crypto.decrypt(envelope, aad=AAD) == PLAINTEXT


def test_envelope_is_versioned_and_hides_plaintext():
    envelope = crypto.encrypt(PLAINTEXT, aad=AAD)
    assert envelope[0] == crypto.FORMAT_VERSION == crypto.envelope_version(envelope)
    assert b"ROUNDTRIP-MARKER-1" not in envelope


def test_repeated_encryption_uses_fresh_nonce():
    key = _key()
    a = crypto.encrypt(PLAINTEXT, aad=AAD, key=key)
    b = crypto.encrypt(PLAINTEXT, aad=AAD, key=key)
    assert a != b
    assert a[1:13] != b[1:13]
    assert crypto.decrypt(a, aad=AAD, key=key) == crypto.decrypt(b, aad=AAD, key=key)


def test_wrong_key_fails():
    envelope = crypto.encrypt(PLAINTEXT, aad=AAD, key=_key())
    with pytest.raises(crypto.CredentialDecryptionError):
        crypto.decrypt(envelope, aad=AAD, key=_key())


@pytest.mark.parametrize("index", [0, 1, 12, 13, -1])
def test_any_flipped_byte_is_rejected(index):
    key = _key()
    envelope = bytearray(crypto.encrypt(PLAINTEXT, aad=AAD, key=key))
    envelope[index] ^= 0x01
    with pytest.raises(crypto.CredentialDecryptionError):
        crypto.decrypt(bytes(envelope), aad=AAD, key=key)


@pytest.mark.parametrize("blob", [b"", b"\x01", b"\x01" + b"\x00" * 20, b"\x02" + b"\x00" * 40])
def test_malformed_envelopes_are_rejected(blob):
    with pytest.raises(crypto.CredentialDecryptionError):
        crypto.decrypt(blob, aad=AAD, key=_key())


def test_non_bytes_envelope_is_rejected():
    with pytest.raises(crypto.CredentialDecryptionError):
        crypto.decrypt("not-bytes", aad=AAD, key=_key())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "other",
    [
        {"credential_id": "cred-2", "scope_key": "device:d1", "credential_type": "snmpv3_auth"},
        {"credential_id": "cred-1", "scope_key": "device:d2", "credential_type": "snmpv3_auth"},
        {"credential_id": "cred-1", "scope_key": "device:d1", "credential_type": "snmpv3_priv"},
        {
            "credential_id": "cred-1",
            "scope_key": "device:d1",
            "credential_type": "snmpv3_auth",
            "version": 2,
        },
    ],
)
def test_ciphertext_is_bound_to_credential_identity(other):
    key = _key()
    envelope = crypto.encrypt(PLAINTEXT, aad=AAD, key=key)
    with pytest.raises(crypto.CredentialDecryptionError):
        crypto.decrypt(envelope, aad=crypto.build_aad(**other), key=key)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "not base64 !!",
        _b64(b"short"),
        _b64(os.urandom(16)),
        _b64(os.urandom(64)),
        _b64(bytes(32)),
    ],
)
def test_missing_or_invalid_key_fails_closed(monkeypatch, value):
    monkeypatch.setattr(
        settings, "credential_encryption_key", SecretStr(value) if value is not None else None
    )
    with pytest.raises(crypto.CredentialKeyError):
        crypto.encrypt(PLAINTEXT, aad=AAD)
    with pytest.raises(crypto.CredentialKeyError):
        crypto.decrypt(b"\x01" + b"\x00" * 40, aad=AAD)


def test_key_error_message_does_not_echo_the_key(monkeypatch):
    bad = "KEY-LEAK-MARKER-not-valid-base64!!"
    monkeypatch.setattr(settings, "credential_encryption_key", SecretStr(bad))
    with pytest.raises(crypto.CredentialKeyError) as info:
        crypto.load_key()
    assert "KEY-LEAK-MARKER" not in str(info.value)
    assert "KEY-LEAK-MARKER" not in repr(info.value)


def test_key_can_be_loaded_from_file(monkeypatch, tmp_path):
    raw = _key()
    path = tmp_path / "key"
    path.write_text(_b64(raw) + "\n")
    monkeypatch.setattr(settings, "credential_encryption_key", None)
    monkeypatch.setattr(settings, "credential_encryption_key_file", str(path))
    assert crypto.load_key() == raw


def test_missing_key_file_and_dual_configuration_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "credential_encryption_key", None)
    monkeypatch.setattr(settings, "credential_encryption_key_file", str(tmp_path / "absent"))
    with pytest.raises(crypto.CredentialKeyError):
        crypto.load_key()

    path = tmp_path / "key"
    path.write_text(_b64(_key()))
    monkeypatch.setattr(settings, "credential_encryption_key", SecretStr(_b64(_key())))
    monkeypatch.setattr(settings, "credential_encryption_key_file", str(path))
    with pytest.raises(crypto.CredentialKeyError):
        crypto.load_key()


def test_production_startup_rejects_configured_but_invalid_key(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "credential_encryption_key", SecretStr("garbage"))
    with pytest.raises(crypto.CredentialKeyError):
        crypto.validate_credential_key_configuration()


def test_missing_key_does_not_block_startup_but_warns(monkeypatch, caplog):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "credential_encryption_key", None)
    with caplog.at_level("WARNING"):
        crypto.validate_credential_key_configuration()
    assert "DISABLED" in caplog.text
