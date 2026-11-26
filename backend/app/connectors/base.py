"""Connector interface shared by SNMP (M13), UniFi (M14) and later adapters.

A connector is read-only: it collects observations about an authorized target
and returns plain data. It never writes inventory itself; reconciliation
(``app.reconcile``) decides what becomes canonical. Errors carry a stable
``code`` and a message that is safe to show to an operator and never contains
credentials, community strings or raw device responses.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ConnectorError(Exception):
    """Failure with a stable machine-readable ``code`` and a safe message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Connector(ABC):
    """Interface every connector implements."""

    #: Stable identifier, e.g. ``"snmp"``; used as observation ``source``.
    name: str

    @abstractmethod
    async def test_connection(self, target: Any) -> dict[str, Any]:
        """Cheap reachability/credential check. Returns non-secret facts only."""

    @abstractmethod
    async def collect_identity(self, target: Any) -> dict[str, Any]:
        """Collect identity facts. Missing data is ``None``, never a guess."""


_REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    if not getattr(cls, "name", None):
        raise ValueError("connector must define a name")
    if cls.name in _REGISTRY:
        raise ValueError(f"connector {cls.name!r} already registered")
    _REGISTRY[cls.name] = cls
    return cls


def registry() -> dict[str, type[Connector]]:
    return dict(_REGISTRY)
