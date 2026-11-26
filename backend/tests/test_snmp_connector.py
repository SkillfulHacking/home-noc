"""M13 SNMPv3 connector: fake-transport unit tests and a real loopback USM agent."""
from __future__ import annotations

import asyncio
import socket
from collections.abc import Sequence

import pytest
from pydantic import SecretStr

from app.connectors import registry
from app.connectors.base import ConnectorError
from app.connectors.snmp import (
    ALLOWED_OIDS,
    MISSING,
    PySnmpTransport,
    SnmpConnector,
    SnmpTarget,
    UsmCredentials,
    normalize,
)

AUTH = "authpass-MARKER-1234"  # noqa: S105 - fixture
PRIV = "privpass-MARKER-1234"  # noqa: S105 - fixture


def creds(**kw):
    base = {"username": "monitor", "auth_protocol": "SHA256", "auth_key": SecretStr(AUTH),
            "priv_protocol": "AES128", "priv_key": SecretStr(PRIV)}
    return UsmCredentials(**{**base, **kw})


class FakeTransport:
    def __init__(self, values=None, error=None):
        self.values, self.error, self.requested = values or {}, error, []

    async def get(self, target, oids: Sequence[str]):
        self.requested.append(list(oids))
        if self.error:
            raise self.error
        return {oid: self.values.get(oid, MISSING) for oid in oids}


def run(coro):
    return asyncio.run(coro)


def target(**kw):
    return SnmpTarget("192.0.2.10", kw.pop("credentials", creds()), **kw)


FULL = {
    ALLOWED_OIDS["sys_descr"]: b"USW-24-PoE, firmware 7.1",
    ALLOWED_OIDS["sys_object_id"]: "1.3.6.1.4.1.41112.1.6",
    ALLOWED_OIDS["sys_uptime"]: 123456,
    ALLOWED_OIDS["sys_name"]: b"core-switch",
    ALLOWED_OIDS["engine_id"]: b"\x80\x00\xa1\x30\x05abcdef",
}


def test_registered_and_identity_collected():
    assert "snmp" in registry()
    t = FakeTransport(FULL)
    facts = run(SnmpConnector(t).collect_identity(target()))
    assert facts["sys_name"] == "core-switch"
    assert facts["sys_object_id"] == "1.3.6.1.4.1.41112.1.6"
    assert facts["sys_uptime"] == 1234
    assert facts["identity_key"] == facts["engine_id"] == "8000a13005616263646566"


def test_only_allowlisted_scalar_oids_requested():
    t = FakeTransport(FULL)
    run(SnmpConnector(t).collect_identity(target()))
    assert set(t.requested[0]) == set(ALLOWED_OIDS.values())


def test_missing_markers_never_become_strings():
    facts = run(SnmpConnector(FakeTransport({})).collect_identity(target()))
    assert all(facts[k] is None for k in ALLOWED_OIDS)
    assert facts["identity_key"] is None
    assert "model" not in facts and "serial" not in facts


@pytest.mark.parametrize("value", [b"", b"   ", "\x00\x01", MISSING, 5, None])
def test_blank_or_invalid_text_is_missing(value):
    assert normalize({"sys_name": value})["sys_name"] is None


def test_text_is_sanitized_and_truncated():
    out = normalize({"sys_descr": "a\x00b\x1b[31m" + "x" * 2000, "sys_object_id": "not an oid",
                     "sys_uptime": -5, "engine_id": b"\x01"})
    assert "\x00" not in out["sys_descr"] and "\x1b" not in out["sys_descr"]
    assert len(out["sys_descr"]) == 512
    assert out["sys_object_id"] is None and out["sys_uptime"] is None and out["engine_id"] is None


def test_identity_falls_back_to_object_id_and_name():
    vals = {k: v for k, v in FULL.items() if k != ALLOWED_OIDS["engine_id"]}
    facts = run(SnmpConnector(FakeTransport(vals)).collect_identity(target()))
    assert facts["identity_key"] == "1.3.6.1.4.1.41112.1.6|core-switch"


@pytest.mark.parametrize("bad", [creds(username=""), creds(auth_key=SecretStr("")),
                                 creds(priv_key=SecretStr(""))])
def test_incomplete_credentials_rejected_without_transport(bad):
    t = FakeTransport(FULL)
    with pytest.raises(ConnectorError) as exc:
        run(SnmpConnector(t).collect_identity(target(credentials=bad)))
    assert exc.value.code == "credentials_incomplete" and t.requested == []


def test_secrets_not_in_repr_or_error_text():
    t = target()
    assert AUTH not in repr(t) and PRIV not in repr(t) and AUTH not in repr(t.credentials)
    err = ConnectorError("timeout", "No response from the SNMP agent")
    assert AUTH not in str(err)


def test_test_connection_returns_only_non_secret_facts():
    out = run(SnmpConnector(FakeTransport(FULL)).test_connection(target()))
    assert set(out) == {"sys_name", "sys_object_id", "identity_key"}


# ---- real pysnmp transport against an in-process loopback USM agent ----------

def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _with_agent(port, client_coro_factory):
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import cmdrsp, context

    eng = engine.SnmpEngine()
    config.add_transport(eng, udp.DOMAIN_NAME,
                         udp.UdpTransport().open_server_mode(("127.0.0.1", port)))
    config.add_v3_user(eng, "monitor", config.USM_AUTH_HMAC192_SHA256, AUTH,
                       config.USM_PRIV_CFB128_AES, PRIV)
    config.add_vacm_user(eng, 3, "monitor", "authPriv", (1, 3, 6), (1, 3, 6))
    cmdrsp.GetCommandResponder(eng, context.SnmpContext(eng))
    try:
        return await client_coro_factory()
    finally:
        eng.close_dispatcher()


def test_real_transport_against_loopback_agent():
    port = _free_udp_port()
    conn = SnmpConnector(PySnmpTransport())

    async def go():
        return await conn.collect_identity(SnmpTarget("127.0.0.1", creds(), port=port))

    facts = run(_with_agent(port, go))
    assert facts["sys_descr"] and facts["engine_id"] and facts["sys_uptime"] is not None
    assert facts["sys_object_id"] is None or facts["sys_object_id"][0].isdigit()


def test_real_transport_wrong_secret_fails_authentication():
    port = _free_udp_port()
    conn = SnmpConnector(PySnmpTransport())

    async def go():
        bad = creds(auth_key=SecretStr("wrong-passphrase-99"))
        with pytest.raises(ConnectorError) as exc:
            await conn.collect_identity(SnmpTarget("127.0.0.1", bad, port=port))
        return exc.value

    err = run(_with_agent(port, go))
    assert err.code == "authentication_failed"
    assert "wrong-passphrase" not in err.message and AUTH not in err.message


def test_real_transport_timeout_when_no_agent():
    port = _free_udp_port()
    with pytest.raises(ConnectorError) as exc:
        run(SnmpConnector(PySnmpTransport()).collect_identity(
            SnmpTarget("127.0.0.1", creds(), port=port)))
    assert exc.value.code in {"timeout", "snmp_error"}
