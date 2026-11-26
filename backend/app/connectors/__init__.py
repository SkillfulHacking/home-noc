"""Pluggable read-only connectors (M13, issue #16)."""
from .base import Connector, ConnectorError, register, registry

__all__ = ["Connector", "ConnectorError", "register", "registry"]
