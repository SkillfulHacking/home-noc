"""Shared SNMP device-poll service used by the API route and scheduled jobs (M15/M16)."""
from __future__ import annotations

from typing import Any

from pydantic import SecretStr
from sqlalchemy.orm import Session

from .. import credentials as creds_svc
from .. import crypto
from ..models import Device
from .base import ConnectorError
from .snmp import SnmpConnector, SnmpTarget, SnmpTransport, UsmCredentials
from .snmp_interfaces import collect_interfaces
from .snmp_sync import persist_poll


def load_usm(db: Session, device_id: str) -> UsmCredentials:
    """Decrypt the device's authPriv credentials in-process. Raises ``ConnectorError``."""
    scope = creds_svc.Scope.device(device_id)
    auth = creds_svc.find(db, scope, "snmpv3_auth")
    priv = creds_svc.find(db, scope, "snmpv3_priv")
    if auth is None or priv is None:
        raise ConnectorError(
            "credentials_missing",
            "SNMPv3 authentication and privacy credentials must both be configured",
        )
    try:
        auth_secret, priv_secret = creds_svc.reveal(auth), creds_svc.reveal(priv)
    except crypto.CredentialCryptoError:
        raise ConnectorError(
            "credentials_unavailable", "Credential encryption is not available"
        ) from None
    return UsmCredentials(
        username=str((auth.meta or {}).get("username", "")),
        auth_protocol=str((auth.meta or {}).get("protocol", "SHA256")),
        auth_key=SecretStr(str(auth_secret.get("password", ""))),
        priv_protocol=str((priv.meta or {}).get("protocol", "AES128")),
        priv_key=SecretStr(str(priv_secret.get("password", ""))),
    )


async def collect(transport: SnmpTransport, target: SnmpTarget) -> tuple[dict, dict]:
    connector = SnmpConnector(transport)
    facts = await connector.collect_identity(target)
    return facts, await collect_interfaces(transport, target, facts)


def persist(db: Session, device: Device, address: str, facts: dict, iface: dict) -> dict[str, Any]:
    return persist_poll(db, device, address, facts, iface)
