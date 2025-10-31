# backend/app/models.py
from sqlalchemy import String, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from typing import Optional
from datetime import datetime

from .db import Base

class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)   # store list under {"v": [...]}
    mac: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    discovery_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    serial: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    roles: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # {"v":[...]}
    ports: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # {"v":[{...}]}
    snmp: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    api: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(String(4096), nullable=True)
