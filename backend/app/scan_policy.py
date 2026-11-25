"""Runtime scan policy (M08A, issue #66).

This module owns three things and nothing else:

1. **Address classification** -- exact RFC1918 membership (never
   ``ipaddress.is_private``), prohibited special-use blocks and public space.
2. **The persisted policy** -- one SQLite row holding the administrator's
   private/public toggles, strict allowlists and exclusions, plus an
   append-only audit trail. Updates are validated as a whole, guarded by an
   optimistic ``revision`` and written atomically with their audit row.
3. **The deployment ceiling** -- ``SCAN_ALLOWED_CIDRS`` / ``SCAN_ALLOW_PUBLIC``
   from the environment. Runtime policy can only narrow the ceiling, never
   widen it, and an explicit ``SCAN_ALLOW_PUBLIC=false`` blocks public scanning.

Precedence (any applicable denial wins): prohibited special-use space >
exclusions > deployment ceiling > runtime toggles/allowlists > profile limits.

The API and the worker both call ``load_policy`` so neither trusts the other's
view of authorization. Anything unexpected (missing row in production, invalid
stored data, database unavailable) raises ``PolicyUnavailable`` and callers
treat that as *deny*.
"""
from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from .config import settings
from .models import ScanPolicy, ScanPolicyAudit

logger = logging.getLogger("home_noc.scan_policy")

POLICY_ROW_ID = 1
MAX_POLICY_ENTRIES = 64       # per allowlist
MAX_EXCLUSIONS = 256
MIN_PUBLIC_PREFIX = 16        # a public allowlist entry may not be wider than a /16
MAX_ENTRY_LENGTH = 64

V4 = ipaddress.IPv4Network

# RFC 1918, spelled out. Deliberately NOT ``is_private`` (which also covers
# loopback, link-local, CGNAT, documentation ranges, ...).
RFC1918: tuple[V4, ...] = (
    V4("10.0.0.0/8"), V4("172.16.0.0/12"), V4("192.168.0.0/16"),
)

# Never scannable whatever any policy or ceiling says.
FORBIDDEN_BLOCKS: tuple[tuple[V4, str], ...] = (
    (V4("0.0.0.0/8"), "unspecified"),
    (V4("127.0.0.0/8"), "loopback"),
    # Includes the 169.254.169.254 cloud metadata endpoint.
    (V4("169.254.0.0/16"), "link-local / cloud metadata"),
    (V4("224.0.0.0/4"), "multicast"),
    (V4("240.0.0.0/4"), "reserved / broadcast"),  # includes 255.255.255.255
)

# Non-global, non-RFC1918 special-use space (CGNAT, documentation, benchmarking,
# IETF protocol assignments). Never part of runtime policy; only reachable when
# an operator lists it explicitly in the *environment* ceiling (legacy behaviour).
SPECIAL_USE: tuple[V4, ...] = (
    V4("100.64.0.0/10"), V4("192.0.0.0/24"), V4("192.0.2.0/24"), V4("192.88.99.0/24"),
    V4("198.18.0.0/15"), V4("198.51.100.0/24"), V4("203.0.113.0/24"),
)

PRIVATE, PUBLIC, SPECIAL, MIXED, FORBIDDEN = "private", "public", "special", "mixed", "forbidden"


def classify(net: V4) -> tuple[str, str | None]:
    """Classify a whole network. Overlap-based, so a wide range cannot hide a
    forbidden or private block inside it. Returns ``(kind, reason)``."""
    for block, reason in FORBIDDEN_BLOCKS:
        if net.overlaps(block):
            return FORBIDDEN, reason
    if any(net.subnet_of(b) for b in RFC1918):
        return PRIVATE, None
    if any(net.overlaps(b) for b in RFC1918):
        return MIXED, "spans private and non-private space"
    if any(net.subnet_of(b) for b in SPECIAL_USE):
        return SPECIAL, None
    if any(net.overlaps(b) for b in SPECIAL_USE):
        return MIXED, "spans special-use and public space"
    return PUBLIC, None


def covered(net: V4, collapsed: Iterable[V4]) -> bool:
    return any(net.subnet_of(c) for c in collapsed)


def collapse(items: Iterable[V4]) -> list[V4]:
    return list(ipaddress.collapse_addresses(items))


# ------------------------------------------------------------------ errors

class PolicyUnavailable(Exception):
    """The persisted policy cannot be trusted right now. Callers must deny."""

    def __init__(self, code: str, message: str, *, transient: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.transient = transient


class PolicyValidationError(ValueError):
    def __init__(self, code: str, message: str, field: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field


class PolicyConflict(Exception):
    def __init__(self, current: PolicyState):
        super().__init__("revision conflict")
        self.current = current


class PolicyConfirmationRequired(Exception):
    def __init__(self, reasons: list[str], public: bool):
        super().__init__("confirmation required")
        self.reasons = reasons
        self.public = public


# ------------------------------------------------------------------- state

@dataclass(frozen=True)
class PolicyState:
    revision: int
    private_enabled: bool
    private_allowlist: tuple[str, ...]
    public_enabled: bool
    public_allowlist: tuple[str, ...]
    exclusions: tuple[str, ...]
    bootstrap_origin: str
    updated_at: datetime
    updated_by: str
    # Strict: only ``private_allowlist`` is authorized (empty list = nothing).
    private_strict: bool = False

    def config(self) -> dict:
        """The administrator-controlled part, as stored in audit rows."""
        return {
            "private_enabled": self.private_enabled,
            "private_strict": self.private_strict,
            "private_allowlist": list(self.private_allowlist),
            "public_enabled": self.public_enabled,
            "public_allowlist": list(self.public_allowlist),
            "exclusions": list(self.exclusions),
        }

    # Parsed views (entries were validated on load/save, so these cannot fail).
    def private_nets(self) -> list[V4]:
        return collapse(V4(x) for x in self.private_allowlist)

    def public_nets(self) -> list[V4]:
        return collapse(V4(x) for x in self.public_allowlist)

    def exclusion_nets(self) -> list[V4]:
        return [V4(x) for x in self.exclusions]


@dataclass(frozen=True)
class DeploymentCeiling:
    """Immutable restrictions from the environment."""

    restricted: bool            # SCAN_ALLOWED_CIDRS was set (even if unusable)
    networks: tuple[V4, ...]    # valid IPv4 entries, collapsed
    public_blocked: bool        # SCAN_ALLOW_PUBLIC explicitly false


def deployment_ceiling() -> DeploymentCeiling:
    raw = (settings.scan_allowed_cidrs_raw or "").strip()
    nets: list[V4] = []
    for item in settings.scan_allowed_cidrs:
        try:
            net = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError:
            logger.error("Ignoring invalid SCAN_ALLOWED_CIDRS entry")
            continue
        if net.version == 4:
            nets.append(net)  # type: ignore[arg-type]
    # Only an *explicit* false is a restriction; the unset default is not.
    public_blocked = settings.scan_allow_public_env is False
    return DeploymentCeiling(bool(raw), tuple(collapse(nets)), public_blocked)


# -------------------------------------------------------------- validation

def _parse_entry(raw: object, field: str) -> V4:
    if not isinstance(raw, str):
        raise PolicyValidationError("invalid_cidr", "Entries must be strings", field)
    text = raw.strip()
    if not text or len(text) > MAX_ENTRY_LENGTH:
        raise PolicyValidationError("invalid_cidr", "Entry is empty or too long", field)
    shown = text[:MAX_ENTRY_LENGTH]
    if text.startswith("-") or any(c.isspace() for c in text):
        raise PolicyValidationError("invalid_cidr", f"{shown!r} is malformed", field)
    try:
        if "/" in text:
            # strict: host bits set (10.1.2.3/8) is rejected rather than silently
            # widened to the enclosing network.
            return V4(text, strict=True)
        return V4(f"{ipaddress.IPv4Address(text)}/32")
    except ValueError:
        raise PolicyValidationError(
            "invalid_cidr", f"{shown!r} is not a canonical IPv4 address or CIDR", field
        ) from None


def _parse_list(raw: object, field: str, limit: int) -> list[V4]:
    if not isinstance(raw, (list, tuple)):
        raise PolicyValidationError("invalid_list", "Expected a list", field)
    if len(raw) > limit:
        raise PolicyValidationError("too_many_entries", f"At most {limit} entries", field)
    nets = [_parse_entry(item, field) for item in raw]
    if len(set(nets)) != len(nets):
        raise PolicyValidationError("duplicate_entry", "Duplicate entries are not allowed", field)
    return nets


def normalize_config(
    *, private_allowlist: object, public_allowlist: object, exclusions: object,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Validate and normalize the three CIDR lists. Raises ``PolicyValidationError``."""
    private = _parse_list(private_allowlist, "private_allowlist", MAX_POLICY_ENTRIES)
    for net in private:
        kind, _ = classify(net)
        if kind != PRIVATE:
            raise PolicyValidationError(
                "not_rfc1918",
                f"{net} is not inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16",
                "private_allowlist",
            )
    public = _parse_list(public_allowlist, "public_allowlist", MAX_POLICY_ENTRIES)
    for net in public:
        kind, reason = classify(net)
        if kind != PUBLIC:
            raise PolicyValidationError(
                "not_public",
                f"{net} is not a public range ({reason or kind}); "
                "private and special-use addresses cannot be listed here",
                "public_allowlist",
            )
        if net.prefixlen < MIN_PUBLIC_PREFIX:
            raise PolicyValidationError(
                "public_range_too_wide",
                f"{net} is wider than /{MIN_PUBLIC_PREFIX}; list only owned or approved ranges",
                "public_allowlist",
            )
    excl = _parse_list(exclusions, "exclusions", MAX_EXCLUSIONS)
    return (
        tuple(str(n) for n in private),
        tuple(str(n) for n in public),
        tuple(str(n) for n in excl),
    )


def check_against_ceiling(
    private: Iterable[str], public: Iterable[str], ceiling: DeploymentCeiling,
) -> None:
    """Runtime lists may only narrow the deployment ceiling."""
    if ceiling.restricted:
        for field, items in (("private_allowlist", private), ("public_allowlist", public)):
            for item in items:
                if not covered(V4(item), ceiling.networks):
                    raise PolicyValidationError(
                        "outside_deployment_ceiling",
                        f"{item} is outside the deployment's SCAN_ALLOWED_CIDRS ceiling "
                        "(set in the environment, not editable here)",
                        field,
                    )


# ------------------------------------------------------------- persistence

def _now() -> datetime:
    return datetime.now(UTC)


def _from_row(row: ScanPolicy) -> PolicyState:
    try:
        if row.id != POLICY_ROW_ID or not isinstance(row.revision, int) or row.revision < 1:
            raise PolicyValidationError("invalid_row", "bad row identity")
        if not all(
            isinstance(v, bool)
            for v in (row.private_enabled, row.public_enabled, row.private_strict)
        ):
            raise PolicyValidationError("invalid_row", "bad toggle")
        private, public, excl = normalize_config(
            private_allowlist=(row.private_allowlist or {}).get("v"),
            public_allowlist=(row.public_allowlist or {}).get("v"),
            exclusions=(row.exclusions or {}).get("v"),
        )
        check_strict_combination(row.private_strict, private)
    except (PolicyValidationError, AttributeError, TypeError):
        # Never guess at a corrupted authorization record: deny.
        logger.error("persisted scan policy failed validation; denying all scans")
        raise PolicyUnavailable(
            "policy_invalid", "The stored scan policy is invalid; scanning is disabled"
        ) from None
    return PolicyState(
        revision=row.revision, private_enabled=row.private_enabled,
        private_allowlist=private, public_enabled=row.public_enabled,
        public_allowlist=public, exclusions=excl,
        bootstrap_origin=row.bootstrap_origin, updated_at=row.updated_at,
        updated_by=row.updated_by, private_strict=row.private_strict,
    )


def check_strict_combination(strict: bool, private: Iterable[str]) -> None:
    """A private allowlist only has meaning in strict mode. Refusing the other
    combination removes any ambiguity about what a populated list authorizes."""
    if not strict and list(private):
        raise PolicyValidationError(
            "allowlist_requires_strict",
            "A private allowlist is only applied in strict mode; enable strict mode or "
            "clear the list",
            "private_allowlist",
        )


def _nonproduction() -> bool:
    return not settings.is_production or settings.app_env in {"dev", "test"}


def seed_dev_default(db: Session) -> None:
    """Dev/test only: the schema is created by ``create_all`` (no migration ran),
    so seed what a fresh install would get. Production never does this."""
    db.add(ScanPolicy(
        id=POLICY_ROW_ID, revision=1, private_enabled=True, private_strict=False,
        private_allowlist={"v": []},
        public_enabled=False, public_allowlist={"v": []}, exclusions={"v": []},
        bootstrap_origin="dev_default", updated_at=_now(), updated_by="bootstrap",
    ))
    try:
        db.commit()
    except IntegrityError:  # another thread seeded concurrently
        db.rollback()


def load_policy(db: Session) -> PolicyState:
    """Read the *current* policy. Raises ``PolicyUnavailable`` (deny) on any problem."""
    try:
        rows = list(db.scalars(
            select(ScanPolicy).execution_options(populate_existing=True)
        ))
        if not rows and _nonproduction():
            seed_dev_default(db)
            rows = list(db.scalars(
                select(ScanPolicy).execution_options(populate_existing=True)
            ))
    except SQLAlchemyError:
        db.rollback()
        logger.error("scan policy could not be read", exc_info=True)
        raise PolicyUnavailable(
            "policy_unavailable", "The scan policy store is unavailable; scanning is disabled",
            transient=True,
        ) from None
    if not rows:
        raise PolicyUnavailable(
            "policy_missing",
            "No scan policy is stored (migrations may not have run); scanning is disabled",
        )
    if len(rows) != 1:
        raise PolicyUnavailable("policy_invalid", "Multiple scan policy rows; scanning is disabled")
    return _from_row(rows[0])


def load_current_policy() -> PolicyState:
    """Load with a private short-lived session (used when a caller has none)."""
    from .db import Base, SessionLocal, engine

    for attempt in (1, 2):
        with SessionLocal() as db:
            try:
                return load_policy(db)
            except PolicyUnavailable as exc:
                # Dev/test databases built without migrations may lack the table.
                if (attempt == 1 and exc.transient and settings.app_env in {"dev", "test"}):
                    from . import models  # noqa: F401
                    Base.metadata.create_all(bind=engine)
                    continue
                raise
    raise PolicyUnavailable("policy_unavailable", "Scan policy unavailable")  # pragma: no cover


def _audit(
    db: Session, *, actor: str, outcome: str, prior: PolicyState | None,
    new_revision: int | None = None, new: dict | None = None,
) -> None:
    db.add(ScanPolicyAudit(
        at=_now(), actor=actor[:255], outcome=outcome[:48],
        prior_revision=prior.revision if prior else None, new_revision=new_revision,
        prior=prior.config() if prior else None, new=new,
    ))


def _safe_submitted(raw: dict) -> dict:
    """Bounded copy of rejected input for the audit trail (non-secret by design)."""
    out: dict = {}
    for key in ("private_enabled", "public_enabled"):
        if isinstance(raw.get(key), bool):
            out[key] = raw[key]
    for key in ("private_allowlist", "public_allowlist", "exclusions"):
        val = raw.get(key)
        if isinstance(val, list) and len(val) <= MAX_EXCLUSIONS:
            out[key] = [str(v)[:MAX_ENTRY_LENGTH] for v in val]
        else:
            out[key] = "<omitted>"
    return out


def record_rejection(db: Session, *, actor: str, outcome: str, submitted: dict) -> None:
    """Audit a refused change in its own transaction. Best effort: a refusal
    changes nothing, so failing to log it must not mask the real error."""
    try:
        db.rollback()
        current = None
        try:
            current = load_policy(db)
        except PolicyUnavailable:
            pass
        _audit(db, actor=actor, outcome=outcome, prior=current, new=_safe_submitted(submitted))
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.error("could not audit rejected scan policy change", exc_info=True)


def broadening_reasons(old: PolicyState, new: PolicyState) -> list[str]:
    reasons: list[str] = []
    if new.private_enabled and not old.private_enabled:
        reasons.append("private_enabled")
    elif new.private_enabled and old.private_strict:
        old_nets = old.private_nets()
        if not new.private_strict:
            reasons.append("private_strict_disabled")  # listed-only/none -> all RFC1918
        elif any(not covered(n, old_nets) for n in new.private_nets()):
            reasons.append("private_allowlist_widened")
    if new.public_enabled:
        if not old.public_enabled:
            reasons.append("public_enabled")
        elif any(not covered(n, old.public_nets()) for n in new.public_nets()):
            reasons.append("public_allowlist_widened")
    new_excl = collapse(new.exclusion_nets())
    if any(not covered(n, new_excl) for n in old.exclusion_nets()):
        reasons.append("exclusion_removed")
    return reasons


def update_policy(
    db: Session, *, actor: str, expected_revision: int,
    private_enabled: bool, private_allowlist: object,
    public_enabled: bool, public_allowlist: object, exclusions: object,
    private_strict: bool = False,
    confirm_broadening: bool = False, confirm_public: bool = False,
    in_transaction: Callable[[Session, PolicyState], None] | None = None,
) -> PolicyState:
    """Validate and atomically apply a policy change.

    The UPDATE is conditional on ``revision == expected_revision`` (lost updates
    become ``PolicyConflict``); the audit row and any ``in_transaction`` work
    (e.g. failing queued jobs the new policy no longer authorizes) commit in the
    same transaction or not at all.
    """
    current = load_policy(db)
    ceiling = deployment_ceiling()

    private, public, excl = normalize_config(
        private_allowlist=private_allowlist, public_allowlist=public_allowlist,
        exclusions=exclusions,
    )
    check_against_ceiling(private, public, ceiling)
    check_strict_combination(private_strict, private)
    if public_enabled and ceiling.public_blocked:
        raise PolicyValidationError(
            "public_blocked_by_deployment",
            "Public scanning is disabled by SCAN_ALLOW_PUBLIC=false in the deployment "
            "environment and cannot be enabled here",
            "public_enabled",
        )
    if expected_revision != current.revision:
        raise PolicyConflict(current)

    candidate = PolicyState(
        revision=current.revision + 1, private_enabled=private_enabled,
        private_allowlist=private, public_enabled=public_enabled,
        public_allowlist=public, exclusions=excl, bootstrap_origin=current.bootstrap_origin,
        updated_at=_now(), updated_by=actor[:255], private_strict=private_strict,
    )
    if candidate.config() == current.config():
        return current  # nothing to do; no revision churn

    reasons = broadening_reasons(current, candidate)
    public_reasons = [r for r in reasons if r.startswith("public_")]
    if reasons and (not confirm_broadening or (public_reasons and not confirm_public)):
        raise PolicyConfirmationRequired(reasons, bool(public_reasons))

    try:
        res = db.execute(
            update(ScanPolicy)
            .where(ScanPolicy.id == POLICY_ROW_ID, ScanPolicy.revision == expected_revision)
            .values(
                revision=candidate.revision, private_enabled=private_enabled,
                private_strict=private_strict,
                private_allowlist={"v": list(private)},
                public_enabled=public_enabled,
                public_allowlist={"v": list(public)}, exclusions={"v": list(excl)},
                updated_at=candidate.updated_at, updated_by=candidate.updated_by,
            )
            .execution_options(synchronize_session=False)
        )
        if res.rowcount != 1:
            db.rollback()
            raise PolicyConflict(load_policy(db))
        _audit(
            db, actor=actor, outcome="applied", prior=current,
            new_revision=candidate.revision, new=candidate.config(),
        )
        if in_transaction is not None:
            in_transaction(db, candidate)
        db.commit()
    except PolicyConflict:
        raise
    except SQLAlchemyError:
        db.rollback()
        logger.error("scan policy update failed", exc_info=True)
        raise PolicyUnavailable(
            "policy_unavailable", "The scan policy could not be saved; nothing was changed",
            transient=True,
        ) from None
    except BaseException:
        db.rollback()  # never leave the policy update half-applied
        raise
    return load_policy(db)


# ----------------------------------------------------------------- display

def effective_view(state: PolicyState, ceiling: DeploymentCeiling) -> dict:
    """What is actually authorized right now (stored policy ∩ ceiling)."""
    def intersect(a: list[V4], b: list[V4]) -> list[V4]:
        out: list[V4] = []
        for x in a:
            for y in b:
                if x.subnet_of(y):
                    out.append(x)
                elif y.subnet_of(x):
                    out.append(y)
        return collapse(out)

    # Strict: only the listed ranges (empty list = none). Otherwise all RFC1918.
    base = state.private_nets() if state.private_strict else list(RFC1918)
    private = intersect(base, list(ceiling.networks)) if ceiling.restricted else base
    # Legacy exception: special-use space the *environment* lists explicitly.
    # Not ordinary private authorization, and never available in strict mode.
    special = (
        [] if state.private_strict
        else [n for n in ceiling.networks if classify(n)[0] == SPECIAL]
    )
    public: list[V4] = []
    if state.public_enabled and not ceiling.public_blocked:
        public = state.public_nets()
        if ceiling.restricted:
            public = intersect(public, list(ceiling.networks))
    return {
        "private_networks": [str(n) for n in private] if state.private_enabled else [],
        "special_use_networks": [str(n) for n in special] if state.private_enabled else [],
        "public_networks": [str(n) for n in public],
        "excluded": list(state.exclusions),
        "private_scanning": state.private_enabled and bool(private or special),
        "public_scanning": bool(public),
    }
