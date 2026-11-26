"""SNMPv3 authPriv read-only identity poller (M13, issue #16).

Safety properties
* Only SNMPv3 with both authentication and privacy (authPriv). SNMPv1/v2c is not
  implemented; ``noAuth``/``authNoPriv`` configurations are rejected.
* Only a fixed allowlist of scalar OIDs is ever requested (GET, never SET/WALK).
* ``noSuchObject``/``noSuchInstance``/``endOfMibView`` and empty values are
  *missing data* (``None``); they never become a model, serial or any string.
* Timeouts and retries are fixed and small; transports are injectable so tests
  never touch a network.
* Secrets live in ``SecretStr`` and are never logged, returned or put in errors.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import SecretStr

from .base import Connector, ConnectorError, register

SNMP_PORT = 161
TIMEOUT_SECONDS = 2.0
RETRIES = 1

# name -> scalar OID. This is the complete set a poller may request.
ALLOWED_OIDS: dict[str, str] = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_uptime": "1.3.6.1.2.1.1.3.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "engine_id": "1.3.6.1.6.3.10.2.1.1.0",  # snmpEngineID: stable, interface-independent
}
_OID_RE = re.compile(r"^\d+(\.\d+){1,31}$")
_MAX_TEXT = {"sys_descr": 512, "sys_name": 255}


class _Missing:
    """Sentinel: agent reported noSuchObject / noSuchInstance / endOfMibView."""

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "MISSING"


MISSING = _Missing()
RawValue = str | bytes | int | _Missing


@dataclass(frozen=True)
class UsmCredentials:
    username: str
    auth_protocol: str
    auth_key: SecretStr = field(repr=False)
    priv_protocol: str
    priv_key: SecretStr = field(repr=False)


@dataclass(frozen=True)
class SnmpTarget:
    address: str
    credentials: UsmCredentials = field(repr=False)
    port: int = SNMP_PORT


class SnmpTransport(Protocol):
    async def get(self, target: SnmpTarget, oids: Sequence[str]) -> dict[str, RawValue]:
        """GET ``oids``; raise ``ConnectorError`` for transport/auth failures."""


def validate_credentials(creds: UsmCredentials) -> None:
    if not creds.username or not creds.auth_key.get_secret_value() \
            or not creds.priv_key.get_secret_value():
        raise ConnectorError(
            "credentials_incomplete", "SNMPv3 authPriv requires username, auth and privacy secrets"
        )


def _clean_text(value: RawValue, limit: int) -> str | None:
    if isinstance(value, _Missing) or value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return None
    text = "".join(ch for ch in value if ch.isprintable() or ch in " \t").strip()
    return text[:limit] if text else None


def normalize(raw: dict[str, RawValue]) -> dict[str, Any]:
    """Convert transport values to the identity facts; unknown/missing -> None."""
    out: dict[str, Any] = {k: None for k in ALLOWED_OIDS}
    for key in ("sys_descr", "sys_name"):
        out[key] = _clean_text(raw.get(key), _MAX_TEXT[key])
    oid = _clean_text(raw.get("sys_object_id"), 256)
    out["sys_object_id"] = oid.lstrip(".") if oid and _OID_RE.match(oid.lstrip(".")) else None
    ticks = raw.get("sys_uptime")
    if isinstance(ticks, int) and not isinstance(ticks, bool) and ticks >= 0:
        out["sys_uptime"] = ticks // 100  # TimeTicks (1/100 s) -> seconds
    engine = raw.get("engine_id")
    if isinstance(engine, (bytes, bytearray)) and 5 <= len(engine) <= 32:
        out["engine_id"] = bytes(engine).hex()
    return out


@register
class SnmpConnector(Connector):
    name = "snmp"

    def __init__(self, transport: SnmpTransport) -> None:
        self._transport = transport

    async def _poll(self, target: SnmpTarget) -> dict[str, Any]:
        validate_credentials(target.credentials)
        names = list(ALLOWED_OIDS)
        oids = [ALLOWED_OIDS[n] for n in names]
        assert set(oids) <= set(ALLOWED_OIDS.values())  # noqa: S101 - allowlist invariant
        reply = await self._transport.get(target, oids)
        # Re-key OID -> name; ignore anything the agent returned that we did not ask for.
        by_name = {n: reply.get(ALLOWED_OIDS[n], MISSING) for n in names}
        return normalize(by_name)

    async def collect_identity(self, target: SnmpTarget) -> dict[str, Any]:
        facts = await self._poll(target)
        # Identity is interface-independent: engine ID, else sysObjectID + sysName.
        # Model/serial are intentionally never derived from MIB-II scalars.
        facts["identity_key"] = facts["engine_id"] or (
            f"{facts['sys_object_id']}|{facts['sys_name']}"
            if facts["sys_object_id"] and facts["sys_name"] else None
        )
        return facts

    async def test_connection(self, target: SnmpTarget) -> dict[str, Any]:
        facts = await self.collect_identity(target)
        return {"sys_name": facts["sys_name"], "sys_object_id": facts["sys_object_id"],
                "identity_key": facts["identity_key"]}


_AUTH = {
    "SHA": "usmHMACSHAAuthProtocol",
    "SHA224": "usmHMAC128SHA224AuthProtocol",
    "SHA256": "usmHMAC192SHA256AuthProtocol",
    "SHA384": "usmHMAC256SHA384AuthProtocol",
    "SHA512": "usmHMAC384SHA512AuthProtocol",
}
_PRIV = {
    "AES128": "usmAesCfb128Protocol",
    "AES192": "usmAesCfb192Protocol",
    "AES256": "usmAesCfb256Protocol",
}


class PySnmpTransport:
    """Real transport (pysnmp). Never used by tests; see ``FakeTransport`` there."""

    async def get(self, target: SnmpTarget, oids: Sequence[str]) -> dict[str, RawValue]:
        from pysnmp.hlapi.v3arch import asyncio as h

        creds = target.credentials
        try:
            auth_proto = getattr(h, _AUTH[creds.auth_protocol])
            priv_proto = getattr(h, _PRIV[creds.priv_protocol])
        except KeyError:
            raise ConnectorError("unsupported_protocol", "Unsupported SNMPv3 protocol") from None
        engine = h.SnmpEngine()
        try:
            user = h.UsmUserData(
                creds.username,
                authKey=creds.auth_key.get_secret_value(),
                privKey=creds.priv_key.get_secret_value(),
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
            transport = await h.UdpTransportTarget.create(
                (target.address, target.port), timeout=TIMEOUT_SECONDS, retries=RETRIES
            )
            err_ind, err_status, _idx, binds = await h.get_cmd(
                engine, user, transport, h.ContextData(),
                *[h.ObjectType(h.ObjectIdentity(o)) for o in oids],
            )
        except ConnectorError:
            raise
        except Exception:  # noqa: BLE001 - library errors may echo parameters
            raise ConnectorError("snmp_error", "SNMP request failed") from None
        finally:
            engine.close_dispatcher()
        if err_ind:
            text = str(err_ind).lower()
            if "timeout" in text or "no snmp response" in text:
                raise ConnectorError("timeout", "No response from the SNMP agent")
            if "wrong" in text or "unknown user" in text or "digest" in text or "decrypt" in text:
                raise ConnectorError("authentication_failed", "SNMPv3 authentication failed")
            raise ConnectorError("snmp_error", "SNMP request failed")
        if err_status:
            # Per-varbind errors (e.g. noSuchName) are treated as missing data below.
            pass
        # pysnmp resolves names symbolically (e.g. "SNMPv2-MIB::sysName.0"), so map by
        # request order, which SNMP guarantees for a GET response.
        values = [_convert(value) for _name, value in binds]
        return {oid: (values[i] if i < len(values) else MISSING) for i, oid in enumerate(oids)}


def _convert(value: Any) -> RawValue:
    from pyasn1.type import univ
    from pysnmp.proto import rfc1902

    cls = type(value).__name__
    if cls in {"NoSuchObject", "NoSuchInstance", "EndOfMibView"}:
        return MISSING
    if isinstance(value, rfc1902.OctetString):
        return bytes(value.asOctets())
    if isinstance(value, univ.ObjectIdentifier):
        return str(value.prettyPrint())
    if isinstance(value, univ.Integer):
        return int(value)
    return MISSING
