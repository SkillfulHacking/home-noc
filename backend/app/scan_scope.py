"""Authorized scan scopes, profiles and preflight validation (M08, issue #11).

Nothing in this module runs a scan. It decides whether a requested scan
*may* run, and describes what it would do. Defaults are fail-closed:

* With no ``SCAN_ALLOWED_CIDRS`` configured, every target is rejected.
* Only IPv4 literals and CIDRs are accepted as targets. Hostnames are
  rejected outright, which removes DNS rebinding / TOCTOU resolution as an
  attack surface (the scanner never resolves a name that was validated).
* Global (public) addresses are rejected unless the operator explicitly
  opts in with ``SCAN_ALLOW_PUBLIC`` *and* the range is allowlisted.
* Loopback, link-local, multicast, unspecified and reserved addresses are
  never scannable.
* Total target count is bounded.
* Free-form scanner flags are never accepted; profiles map to fixed argv
  lists owned by this module.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from enum import StrEnum

from .config import settings

logger = logging.getLogger("home_noc.scan_authorization")

MAX_TARGET_ENTRIES = 64


class ScanProfile(StrEnum):
    DISCOVERY = "discovery"  # gentle: host discovery only, no port probing
    PORTS = "ports"          # limited: a short fixed list of common ports
    SECURITY = "security"    # opt-in: version/script checks, never default


@dataclass(frozen=True)
class ProfileSpec:
    name: ScanProfile
    description: str
    intrusive: bool
    max_hosts: int
    timeout_seconds: int
    max_concurrency: int
    # Fixed argv fragment. Never built from user input.
    argv: tuple[str, ...]


PROFILES: dict[ScanProfile, ProfileSpec] = {
    ScanProfile.DISCOVERY: ProfileSpec(
        ScanProfile.DISCOVERY,
        "Gentle host discovery (ping/ARP). No port probing.",
        False, 1024, 300, 16,
        ("-sn", "-T2"),
    ),
    ScanProfile.PORTS: ProfileSpec(
        ScanProfile.PORTS,
        "Limited TCP connect scan of a short fixed list of common ports.",
        False, 256, 900, 8,
        ("-sT", "-T3", "--top-ports", "20"),
    ),
    ScanProfile.SECURITY: ProfileSpec(
        ScanProfile.SECURITY,
        "Opt-in service/version detection. Only with explicit enablement.",
        True, 64, 1800, 4,
        ("-sT", "-sV", "-T3", "--top-ports", "100"),
    ),
}


class ScopeError(ValueError):
    """A target or request violates the authorized scan scope."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _parse_networks(raw: list[str]) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for item in raw:
        try:
            net = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError:
            logger.error("Ignoring invalid SCAN_ALLOWED_CIDRS entry")
            continue
        if net.version != 4:
            continue
        nets.append(net)  # type: ignore[arg-type]
    return nets


def allowed_networks() -> list[ipaddress.IPv4Network]:
    return _parse_networks(settings.scan_allowed_cidrs)


# Blocks that are never scannable, whatever the allowlist says. A target is
# rejected if it overlaps any of them (not just if its endpoints fall inside),
# so a wide range cannot swallow a forbidden block.
_FORBIDDEN_BLOCKS: tuple[tuple[ipaddress.IPv4Network, str], ...] = (
    (ipaddress.IPv4Network("0.0.0.0/8"), "unspecified"),  # RFC 1122 "this network"
    (ipaddress.IPv4Network("127.0.0.0/8"), "loopback"),
    (ipaddress.IPv4Network("169.254.0.0/16"), "link-local"),
    (ipaddress.IPv4Network("224.0.0.0/4"), "multicast"),
    (ipaddress.IPv4Network("240.0.0.0/4"), "reserved"),  # includes 255.255.255.255
)


def _unscannable_reason(net: ipaddress.IPv4Network) -> str | None:
    for block, reason in _FORBIDDEN_BLOCKS:
        if net.overlaps(block):
            return reason
    return None


def _check_network(net: ipaddress.IPv4Network, allowed: list[ipaddress.IPv4Network]) -> None:
    reason = _unscannable_reason(net)
    if reason:
        raise ScopeError(
            "target_forbidden", f"{net} is or includes {reason} space and cannot be scanned"
        )
    if not any(net.subnet_of(a) for a in allowed):
        raise ScopeError("out_of_scope", f"{net} is outside the authorized scan scope")
    if net.is_global and not settings.scan_allow_public:
        raise ScopeError(
            "public_address", f"{net} is a public address; public scanning is disabled"
        )


def resolve_targets(
    targets: list[str], profile: ScanProfile
) -> tuple[list[ipaddress.IPv4Network], int]:
    """Validate ``targets`` and return (networks, total host count).

    Raises ``ScopeError`` on the first violation.
    """
    allowed = allowed_networks()
    if not allowed:
        raise ScopeError(
            "no_scope_configured",
            "No authorized scan scope is configured (SCAN_ALLOWED_CIDRS); scanning is disabled",
        )
    if not targets:
        raise ScopeError("no_targets", "At least one target is required")
    if len(targets) > MAX_TARGET_ENTRIES:
        raise ScopeError("too_many_entries", f"At most {MAX_TARGET_ENTRIES} targets per request")

    spec = PROFILES[profile]
    nets: list[ipaddress.IPv4Network] = []
    for raw in targets:
        text = raw.strip()
        if not text or len(text) > 64:
            raise ScopeError("invalid_target", "Target is empty or too long")
        if text.startswith("-") or any(c.isspace() for c in text):
            raise ScopeError("invalid_target", "Target looks like a scanner flag or is malformed")
        try:
            # IPv4 address or CIDR only; hostnames are never resolved.
            if "/" in text:
                net = ipaddress.IPv4Network(text, strict=True)
            else:
                net = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(text)}/32")
        except ValueError:
            raise ScopeError(
                "invalid_target",
                "Targets must be IPv4 addresses or CIDRs (hostnames are not accepted)",
            ) from None
        _check_network(net, allowed)
        nets.append(net)

    # Count unique hosts (overlapping entries must not be double counted).
    collapsed = list(ipaddress.collapse_addresses(nets))
    count = sum(_host_count(n) for n in collapsed)
    if count > spec.max_hosts:
        raise ScopeError(
            "range_too_large",
            f"{count} hosts exceeds the {spec.max_hosts}-host limit for the "
            f"'{profile.value}' profile",
        )
    return collapsed, count


def _host_count(net: ipaddress.IPv4Network) -> int:
    if net.prefixlen >= 31:
        return net.num_addresses
    return net.num_addresses - 2  # network and broadcast addresses


def check_profile_enabled(profile: ScanProfile) -> None:
    if PROFILES[profile].intrusive and not settings.scan_security_profile_enabled:
        raise ScopeError(
            "profile_disabled",
            "The security profile is disabled; the operator must enable it explicitly",
        )


def log_authorization(
    *, operator: str, profile: ScanProfile, networks: list[ipaddress.IPv4Network],
    count: int, dry_run: bool, outcome: str,
) -> None:
    """Record who authorized/attempted what. Contains no secrets."""
    logger.info(
        "scan_authorization operator=%s profile=%s targets=%s hosts=%d dry_run=%s outcome=%s",
        operator.replace("\n", " ")[:64],
        profile.value,
        ",".join(str(n) for n in networks)[:512],
        count,
        dry_run,
        outcome,
    )
