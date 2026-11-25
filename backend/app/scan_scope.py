"""Authorized scan scopes, profiles and preflight validation (M08, issue #11).

Nothing in this module runs a scan. It decides whether a requested scan
*may* run, and describes what it would do. Defaults are fail-closed:

* Authorization comes from the runtime policy (``scan_policy``, editable by an
  administrator in the UI) intersected with the immutable environment ceiling
  (``SCAN_ALLOWED_CIDRS`` / ``SCAN_ALLOW_PUBLIC``). An unreadable or invalid
  stored policy denies everything.
* Only IPv4 literals and CIDRs are accepted as targets. Hostnames are
  rejected outright, which removes DNS rebinding / TOCTOU resolution as an
  attack surface (the scanner never resolves a name that was validated).
* Private scanning covers exactly RFC1918. Public addresses need the
  administrator opt-in *and* an explicit public allowlist entry.
* Loopback, link-local (incl. cloud metadata), multicast, unspecified and
  reserved addresses are never scannable, and ranges that are only partly
  authorized (mixed, or overlapping an exclusion) are rejected whole.
* Total target count is bounded.
* Free-form scanner flags are never accepted; profiles map to fixed argv
  lists owned by this module.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from enum import StrEnum

from . import scan_policy
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
        "Gentle ICMP echo host discovery. No port probing.",
        False, 1024, 300, 16,
        (),
    ),
    ScanProfile.PORTS: ProfileSpec(
        ScanProfile.PORTS,
        "Limited TCP connect scan of a short fixed list of common ports.",
        False, 256, 900, 8,
        (),
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
    """The environment ceiling as configured (legacy view, for the UI)."""
    return _parse_networks(settings.scan_allowed_cidrs)


def _is_edge_address(net: ipaddress.IPv4Network, blocks: list[ipaddress.IPv4Network]) -> bool:
    """A single address that is the network or broadcast address of an authorized
    block (e.g. 192.168.1.255 of 192.168.1.0/24) is not a host."""
    if net.prefixlen != 32:
        return False
    addr = net.network_address
    return any(
        b.prefixlen < 31 and addr in (b.network_address, b.broadcast_address) for b in blocks
    )


def _check_network(
    net: ipaddress.IPv4Network,
    policy: scan_policy.PolicyState,
    ceiling: scan_policy.DeploymentCeiling,
    excluded: list[ipaddress.IPv4Network],
    private_blocks: list[ipaddress.IPv4Network],
) -> str:
    """Authorize one validated network; returns its class. Any denial wins and
    the whole range must be authorized, not just its first address."""
    kind, reason = scan_policy.classify(net)
    if kind == scan_policy.FORBIDDEN:
        raise ScopeError(
            "target_forbidden", f"{net} is or includes {reason} space and cannot be scanned"
        )
    if kind == scan_policy.MIXED:
        raise ScopeError(
            "mixed_range", f"{net} {reason}; submit ranges that are entirely authorized"
        )
    if any(net.overlaps(x) for x in excluded):
        raise ScopeError("excluded_target", f"{net} is or includes an excluded address")
    if ceiling.restricted and not scan_policy.covered(net, ceiling.networks):
        raise ScopeError(
            "out_of_scope",
            f"{net} is outside the deployment's SCAN_ALLOWED_CIDRS ceiling",
        )

    if kind == scan_policy.PUBLIC:
        if ceiling.public_blocked or not policy.public_enabled:
            raise ScopeError(
                "public_address", f"{net} is a public address; public scanning is disabled"
            )
        if not scan_policy.covered(net, policy.public_nets()):
            raise ScopeError(
                "public_not_allowlisted",
                f"{net} is not inside an explicitly allowlisted public range",
            )
        return kind

    # private (RFC1918) or environment-listed special-use space
    if not policy.private_enabled:
        raise ScopeError(
            "private_scanning_disabled",
            "Private-network scanning is disabled in Settings > Security > Scan Policy",
        )
    if kind == scan_policy.SPECIAL:
        # Legacy exception, distinct from RFC1918 authorization: only when the
        # *environment* lists it, and never in strict mode (which authorizes
        # nothing but the listed private ranges).
        if policy.private_strict or not ceiling.restricted:
            raise ScopeError(
                "out_of_scope",
                f"{net} is special-use space; it is scannable only if SCAN_ALLOWED_CIDRS "
                "lists it and strict private mode is off",
            )
        return kind
    if policy.private_strict and not scan_policy.covered(net, policy.private_nets()):
        raise ScopeError(
            "out_of_scope",
            f"{net} is outside the strict private allowlist"
            if policy.private_allowlist
            else "Strict private mode is on and its allowlist is empty, so nothing is authorized",
        )
    if _is_edge_address(net, private_blocks):
        raise ScopeError(
            "target_forbidden", f"{net} is a network or broadcast address and cannot be scanned"
        )
    return kind


def resolve_targets(
    targets: list[str],
    profile: ScanProfile,
    policy: scan_policy.PolicyState | None = None,
) -> tuple[list[ipaddress.IPv4Network], int]:
    """Validate ``targets`` and return (networks, total host count).

    ``policy`` is the *current* runtime policy; when omitted it is loaded fresh
    (the worker and tests). Raises ``ScopeError`` on the first violation; an
    unreadable policy is a denial (``policy_unavailable`` / ``policy_invalid``).
    """
    ceiling = scan_policy.deployment_ceiling()
    if ceiling.restricted and not ceiling.networks:
        raise ScopeError(
            "no_scope_configured",
            "SCAN_ALLOWED_CIDRS is set but contains no usable IPv4 range; scanning is disabled",
        )
    if policy is None:
        try:
            policy = scan_policy.load_current_policy()
        except scan_policy.PolicyUnavailable as exc:
            raise ScopeError(exc.code, exc.message) from None
    excluded = policy.exclusion_nets()
    # Authorization ranges do not describe physical subnet boundaries.
    private_blocks = list(scan_policy.RFC1918)
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
        kind = _check_network(net, policy, ceiling, excluded, private_blocks)
        if kind == scan_policy.PUBLIC and spec.intrusive:
            raise ScopeError(
                "profile_not_allowed_for_public",
                "Only the non-intrusive discovery and ports profiles may target public addresses",
            )
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
