# backend/app/schemas.py
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Literal
from datetime import datetime
from uuid import uuid4

DiscoveryMethod = Literal["scan", "snmp", "api", "manual"]
Role = Literal["switch","router","ap","server","camera","iot","nas","printer"]

class Port(BaseModel):
    port: int
    proto: Literal["tcp", "udp"]
    service: str
    state: Literal["open","closed","filtered"]

class SNMPInfo(BaseModel):
    enabled: bool
    version: Literal["v2c","v3"]
    community_or_user: str = Field(default="masked")

class APIInfo(BaseModel):
    type: Literal["rest","ssh","netconf","vendor"]
    url: str = Field(default="masked")

class DeviceBase(BaseModel):
    hostname: str
    ip: List[str] = []
    mac: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    discovery_method: Optional[DiscoveryMethod] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    serial: Optional[str] = None
    location: Optional[str] = None
    roles: List[Role] = []
    ports: List[Port] = []
    snmp: Optional[SNMPInfo] = None
    api: Optional[APIInfo] = None
    notes: Optional[str] = None

class DeviceCreate(DeviceBase):
    pass

class DeviceRead(DeviceBase):
    model_config = ConfigDict(from_attributes=True)
    id: str

class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    ip: Optional[List[str]] = None
    mac: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    discovery_method: Optional[DiscoveryMethod] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    serial: Optional[str] = None
    location: Optional[str] = None
    roles: Optional[List[Role]] = None
    ports: Optional[List[Port]] = None
    snmp: Optional[SNMPInfo] = None
    api: Optional[APIInfo] = None
    notes: Optional[str] = None

def new_id() -> str:
    return str(uuid4())
