# backend/app/schemas.py
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

DiscoveryMethod = Literal["scan", "snmp", "api", "manual"]


class Port(BaseModel):
    port: int
    proto: str
    service: str | None = None
    state: str | None = None


class SNMPInfo(BaseModel):
    enabled: bool = False
    version: Literal["v2c", "v3"] | None = None
    community_or_user: str | None = Field(default=None, repr=False)


class APIInfo(BaseModel):
    type: Literal["rest", "ssh", "netconf", "vendor"] | None = None
    url: str | None = Field(default=None, repr=False)


Role = Literal["switch", "router", "ap", "server", "camera", "iot", "nas", "printer"]


class DeviceBase(BaseModel):
    hostname: str
    ip: list[str] = []
    mac: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    discovery_method: DiscoveryMethod | None = None
    vendor: str | None = None
    model: str | None = None
    os: str | None = None
    serial: str | None = None
    location: str | None = None
    roles: list[Role] = []
    ports: list[Port] = []
    snmp: SNMPInfo | None = None
    api: APIInfo | None = None
    notes: str | None = None


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    hostname: str | None = None
    ip: list[str] | None = None
    mac: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    discovery_method: DiscoveryMethod | None = None
    vendor: str | None = None
    model: str | None = None
    os: str | None = None
    serial: str | None = None
    location: str | None = None
    roles: list[Role] | None = None
    ports: list[Port] | None = None
    snmp: SNMPInfo | None = None
    api: APIInfo | None = None
    notes: str | None = None


class DeviceRead(DeviceBase):
    model_config = ConfigDict(from_attributes=True)

    id: str


def new_id() -> str:
    return str(uuid4())
