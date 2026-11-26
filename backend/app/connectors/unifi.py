"""Read-only UniFi Network (Integration API) connector (M14, issue #17).

* Only HTTP GET is ever issued; there is no code path that mutates the controller.
* Authentication is an API token sent in ``X-API-KEY``; it is never logged,
  returned or included in errors. Use a read-only (view-only) controller user.
* Paging is bounded (page size and page count); malformed rows are skipped and
  counted, never guessed. Field names tolerate small version differences.
* Redirects are not followed and response bodies are size-capped.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any, Protocol

from ..validators import normalize_ip, normalize_mac
from .base import Connector, ConnectorError, register

API_PREFIX = "/proxy/network/integration/v1"
PAGE_SIZE = 100
MAX_PAGES = 50  # 5000 records per collection
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
REQUEST_TIMEOUT = 10.0


class UniFiHttp(Protocol):
    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET ``path`` under the controller; raise ``ConnectorError`` on failure."""


class HttpxUniFiHttp:
    """Real transport. ``token`` is held privately and never exposed via repr."""

    def __init__(self, base_url: str, token: str, verify_tls: bool = True) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._verify = verify_tls

    def __repr__(self) -> str:
        return f"HttpxUniFiHttp(base={self._base!r})"

    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        import httpx

        try:
            async with httpx.AsyncClient(
                verify=self._verify, timeout=REQUEST_TIMEOUT, follow_redirects=False,
                headers={"X-API-KEY": self._token, "Accept": "application/json"},
            ) as client:
                async with client.stream("GET", f"{self._base}{path}", params=params) as resp:
                    chunks, size = [], 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_RESPONSE_BYTES:  # stop downloading early
                            raise ConnectorError("bad_response", "Controller response too large")
                        chunks.append(chunk)
                    status_code, body = resp.status_code, b"".join(chunks)
        except httpx.TimeoutException:
            raise ConnectorError("timeout", "Controller did not respond in time") from None
        except httpx.ConnectError as exc:
            text = str(exc).lower()
            if "certificate" in text or "ssl" in text or "tls" in text:
                raise ConnectorError("tls_error", "Controller TLS verification failed") from None
            raise ConnectorError("unreachable", "Controller could not be reached") from None
        except httpx.HTTPError:
            raise ConnectorError("unreachable", "Controller could not be reached") from None
        return _decode(status_code, body)


def _decode(status: int, content: bytes) -> Any:
    import json

    if status in (401, 403):
        raise ConnectorError(
            "unauthorized" if status == 401 else "forbidden",
            "The UniFi controller rejected the API token",
        )
    if status == 404:
        raise ConnectorError("not_found", "Endpoint not found; is this UniFi Network 9 or newer?")
    if 300 <= status < 400:
        raise ConnectorError("bad_response", "Unexpected redirect from the controller")
    if status >= 400:
        raise ConnectorError("server_error", f"The controller returned HTTP {status}")
    if len(content) > MAX_RESPONSE_BYTES:
        raise ConnectorError("bad_response", "Controller response too large")
    try:
        return json.loads(content)
    except ValueError:
        raise ConnectorError("bad_response", "Controller returned invalid JSON") from None


def _text(value: Any, limit: int = 255) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable()).strip()
    return cleaned[:limit] or None


def _ident(value: Any) -> str | None:
    text = _text(value, 64)
    return text if text and all(c.isalnum() or c in "-_:." for c in text) else None


def _first(row: dict, *names: str) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return None


def _role_hint(features: Any) -> str | None:
    items = {str(f).lower() for f in features} if isinstance(features, list) else set()
    for needle, role in (("accesspoint", "access_point"), ("switching", "switch"),
                         ("gateway", "router"), ("routing", "router")):
        if needle in items:
            return role
    return None


def _mac_ip(row: dict) -> tuple[str | None, str | None]:
    """Normalized MAC and IPv4 of a controller row; invalid values become None."""
    mac = ip = None
    mac_raw = _first(row, "macAddress", "mac")
    if isinstance(mac_raw, str):
        try:
            mac = normalize_mac(mac_raw)
        except ValueError:
            mac = None
    ip_raw = _first(row, "ipAddress", "ip")
    if isinstance(ip_raw, str):
        try:
            addr = ipaddress.ip_address(normalize_ip(ip_raw))
            ip = str(addr) if addr.version == 4 else None
        except ValueError:
            ip = None
    return mac, ip


def parse_device(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    ident = _ident(row.get("id"))
    mac, ip = _mac_ip(row)
    if not ident or not (mac or ip):
        return None
    return {
        "id": ident, "mac": mac, "ip": ip, "name": _text(row.get("name")),
        "model": _text(row.get("model"), 128),
        "state": (_text(row.get("state"), 32) or "UNKNOWN").upper(),
        "firmware": _text(row.get("firmwareVersion"), 64),
        "adopted": row.get("state") is not None,
        "role_hint": _role_hint(row.get("features")),
    }


def parse_client(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    ident = _ident(row.get("id"))
    mac, ip = _mac_ip(row)
    if not ident or not mac:  # clients need a MAC to be safely deduplicated
        return None
    kind = _text(row.get("type"), 16)
    return {"id": ident, "mac": mac, "ip": ip, "name": _text(row.get("name")),
            "kind": kind.upper() if kind else None}


@register
class UniFiConnector(Connector):
    name = "unifi"

    def __init__(self, http: UniFiHttp) -> None:
        self._http = http

    async def _paginate(self, path: str) -> list[Any]:
        rows: list[Any] = []
        offset = 0
        for _ in range(MAX_PAGES):
            page = await self._http.get_json(path, {"offset": offset, "limit": PAGE_SIZE})
            if not isinstance(page, dict) or not isinstance(page.get("data"), list):
                raise ConnectorError("bad_response", "Unexpected controller response shape")
            data = page["data"]
            rows.extend(data)
            offset += len(data)
            total = page.get("totalCount")
            if not data or (isinstance(total, int) and offset >= total):
                return rows
        raise ConnectorError("bad_response", "Controller returned too many pages")

    async def test_connection(self, target: Any = None) -> dict[str, Any]:
        info = await self._http.get_json(f"{API_PREFIX}/info")
        version = _text(info.get("applicationVersion"), 32) if isinstance(info, dict) else None
        sites = await self._paginate(f"{API_PREFIX}/sites")
        return {"application_version": version, "site_count": len(sites)}

    async def resolve_site(self, wanted: str | None) -> str:
        sites = [s for s in await self._paginate(f"{API_PREFIX}/sites") if isinstance(s, dict)]
        valid = [(s, _ident(s.get("id"))) for s in sites]
        valid = [(s, i) for s, i in valid if i]
        if wanted:
            for s, i in valid:
                if wanted in (i, _text(s.get("name")), _text(s.get("internalReference"))):
                    return i
            raise ConnectorError("site_not_found", "Configured UniFi site was not found")
        if len(valid) == 1:
            return valid[0][1]
        for s, i in valid:
            if _text(s.get("internalReference")) == "default":
                return i
        raise ConnectorError("site_required", "Multiple sites found; configure which to use")

    async def collect_identity(self, target: Sequence[str] | str | None = None) -> dict[str, Any]:
        """Snapshot managed devices and connected clients of one site."""
        site = await self.resolve_site(target if isinstance(target, str) else None)
        raw_devices = await self._paginate(f"{API_PREFIX}/sites/{site}/devices")
        raw_clients = await self._paginate(f"{API_PREFIX}/sites/{site}/clients")
        devices = [d for d in map(parse_device, raw_devices) if d]
        clients = [c for c in map(parse_client, raw_clients) if c]
        return {
            "site": site, "devices": devices, "clients": clients,
            "skipped_devices": len(raw_devices) - len(devices),
            "skipped": (len(raw_devices) - len(devices)) + (len(raw_clients) - len(clients)),
        }
