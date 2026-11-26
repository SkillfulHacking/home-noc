"""M08A: runtime scan policy -- address matrix, precedence and service rules.

Pure/in-memory: nothing here opens a socket or touches a real network.
"""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import pytest
from conftest import set_policy

from app import scan_policy
from app.config import settings
from app.db import SessionLocal
from app.scan_policy import PolicyState
from app.scan_scope import ScanProfile, ScopeError, resolve_targets


def state(**kw) -> PolicyState:
    base = dict(
        revision=1, private_enabled=True, private_allowlist=(), public_enabled=False,
        public_allowlist=(), exclusions=(), bootstrap_origin="fresh",
        updated_at=datetime.now(UTC), updated_by="t",
    )
    base.update(kw)
    return PolicyState(**base)


@pytest.fixture(autouse=True)
def schema():
    from app import models  # noqa: F401
    from app.db import Base, engine

    Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def open_ceiling(monkeypatch):
    """No environment restriction: the fresh-install situation."""
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", None)
    monkeypatch.setattr(settings, "scan_allow_public_env", None)


_DEFAULT = object()


def code(targets, policy=_DEFAULT, profile=ScanProfile.DISCOVERY):
    # ``policy=None`` must reach the resolver unchanged so it loads (and fails
    # closed on) the *stored* policy; only an omitted argument gets a default.
    if policy is _DEFAULT:
        policy = state()
    with pytest.raises(ScopeError) as err:
        resolve_targets(targets, profile, policy)
    return err.value.code


# ----------------------------------------------------------- RFC1918 edges

@pytest.mark.parametrize("target", [
    "10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.0.1",
    "192.168.255.254", "10.1.2.0/24", "172.20.0.0/24", "192.168.1.0/28",
])
def test_rfc1918_targets_are_authorized_on_a_fresh_install(target):
    nets, count = resolve_targets([target], ScanProfile.DISCOVERY, state())
    assert count >= 1 and nets


@pytest.mark.parametrize("target", [
    "9.255.255.254", "11.0.0.1", "172.15.255.254", "172.32.0.1", "192.167.255.254",
    "192.169.0.1",
])
def test_addresses_just_outside_rfc1918_are_public_not_private(target):
    # is_private would be wrong in the other direction too; these are global.
    assert not ipaddress.ip_address(target).is_private
    assert code([target]) == "public_address"


@pytest.mark.parametrize("target", [
    "100.64.0.1",       # CGNAT: is_private is False, but it is not RFC1918
    "192.0.2.1", "198.18.0.1", "203.0.113.5",
])
def test_special_use_space_is_not_scannable_without_an_explicit_env_ceiling(target):
    assert code([target]) == "out_of_scope"


def test_special_use_space_needs_env_listing_and_private_toggle(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "100.64.0.0/24")
    assert resolve_targets(["100.64.0.5"], ScanProfile.DISCOVERY, state())[1] == 1
    assert code(["100.64.0.5"], state(private_enabled=False)) == "private_scanning_disabled"
    # A runtime allowlist/policy can never add such ranges.
    with pytest.raises(scan_policy.PolicyValidationError):
        scan_policy.normalize_config(
            private_allowlist=["100.64.0.0/24"], public_allowlist=[], exclusions=[]
        )


@pytest.mark.parametrize("target,expected", [
    ("127.0.0.1", "target_forbidden"), ("127.0.0.0/8", "target_forbidden"),
    ("169.254.169.254", "target_forbidden"),   # cloud metadata
    ("169.254.0.0/16", "target_forbidden"),
    ("224.0.0.1", "target_forbidden"), ("239.255.255.250", "target_forbidden"),
    # S104: the unspecified address is the prohibited-target fixture under test.
    ("0.0.0.0", "target_forbidden"), ("0.0.0.0/0", "target_forbidden"),  # noqa: S104
    ("240.0.0.1", "target_forbidden"), ("255.255.255.255", "target_forbidden"),
    ("10.0.0.0", "target_forbidden"),            # network address of 10/8
    ("10.255.255.255", "target_forbidden"),      # broadcast of 10/8
    ("192.168.255.255", "target_forbidden"),
])
def test_prohibited_special_use_destinations(target, expected):
    assert code([target]) == expected


@pytest.mark.parametrize("target", [
    "8.0.0.0/5",          # spans 8.x..15.x including 10/8
    "172.0.0.0/8",        # contains 172.16/12 but mostly public
    "192.0.0.0/8",        # contains 192.168/16, 192.0.2/24 ...
    "198.0.0.0/8",        # contains benchmarking 198.18/15 and public space
    "100.0.0.0/8",        # contains CGNAT and public
])
def test_mixed_or_partially_authorized_ranges_are_rejected_whole(target):
    assert code([target], state(public_enabled=True, public_allowlist=("8.8.8.0/24",))) in {
        "mixed_range", "target_forbidden",
    }


def test_range_straddling_the_allowlist_edge_is_rejected():
    policy = state(private_strict=True, private_allowlist=("192.168.1.0/24",))
    assert code(["192.168.0.0/23"], policy) == "out_of_scope"
    assert resolve_targets(["192.168.1.0/25"], ScanProfile.DISCOVERY, policy)[1] == 126


def test_adjacent_allowlist_entries_authorize_a_range_spanning_both():
    policy = state(private_strict=True, private_allowlist=("192.168.2.0/25", "192.168.2.128/25"))
    assert resolve_targets(["192.168.2.0/24"], ScanProfile.DISCOVERY, policy)[1] == 254


@pytest.mark.parametrize("target", [
    "", "example.com", "10.0.0.1;id", "-iL x", "10.0.0.256", "10.0.0.1/33",
    "10.0.0.1/24", "::1", "fe80::1", "10.0.0.1-5", "1" * 65, "0x0a000001", "10.1",
])
def test_malformed_targets(target):
    c = code([target])
    assert c in {"invalid_target"}


def test_oversized_requests_are_bounded():
    many = [f"10.0.0.{i}" for i in range(1, 66)]
    assert code(many) == "too_many_entries"
    assert code(["10.0.0.0/8"]) == "range_too_large"
    assert code(["10.0.0.0/16"], profile=ScanProfile.PORTS) == "range_too_large"


# ------------------------------------------------------------- toggles etc.

def test_private_disable_denies_even_explicit_targets():
    assert code(["10.0.0.5"], state(private_enabled=False)) == "private_scanning_disabled"


def test_strict_mode_semantics_table(monkeypatch):
    t = ["192.168.1.9"]
    # disabled => none (strict or not)
    assert code(t, state(private_enabled=False)) == "private_scanning_disabled"
    assert code(t, state(private_enabled=False, private_strict=True)) == (
        "private_scanning_disabled"
    )
    # enabled, non-strict => RFC1918
    assert resolve_targets(t, ScanProfile.DISCOVERY, state())[1] == 1
    # enabled, strict, empty list => none
    assert code(t, state(private_strict=True)) == "out_of_scope"
    # enabled, strict, populated => only the listed ranges
    listed = state(private_strict=True, private_allowlist=("192.168.1.0/24",))
    assert resolve_targets(t, ScanProfile.DISCOVERY, listed)[1] == 1
    assert code(["10.0.0.5"], listed) == "out_of_scope"


def test_strict_mode_never_authorizes_legacy_special_use_exceptions(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "100.64.0.0/24, 192.168.1.0/24")
    # Non-strict: the environment-listed special-use range is a legacy exception.
    assert resolve_targets(["100.64.0.5"], ScanProfile.DISCOVERY, state())[1] == 1
    # Strict (even listing everything private): it is not authorized.
    strict = state(private_strict=True, private_allowlist=("192.168.1.0/24",))
    assert code(["100.64.0.5"], strict) == "out_of_scope"
    assert code(["100.64.0.5"], state(private_strict=True)) == "out_of_scope"
    view = scan_policy.effective_view(strict, scan_policy.deployment_ceiling())
    assert view["special_use_networks"] == []
    legacy = scan_policy.effective_view(state(), scan_policy.deployment_ceiling())
    assert legacy["special_use_networks"] == ["100.64.0.0/24"]
    # Prohibited ranges stay prohibited in every mode.
    for s in (state(), strict):
        assert code(["169.254.169.254"], s) == "target_forbidden"


def test_allowlist_without_strict_is_rejected_and_persisted_form_fails_closed():
    with pytest.raises(scan_policy.PolicyValidationError) as err:
        scan_policy.check_strict_combination(False, ["192.168.1.0/24"])
    assert err.value.code == "allowlist_requires_strict"
    from app.models import ScanPolicy

    with SessionLocal() as db:
        scan_policy.load_policy(db)
        db.query(ScanPolicy).update({"private_allowlist": {"v": ["192.168.1.0/24"]}})
        db.commit()
        with pytest.raises(scan_policy.PolicyUnavailable) as unavailable:
            scan_policy.load_policy(db)
    assert unavailable.value.code == "policy_invalid"


def test_strict_private_allowlist_is_enforced():
    policy = state(private_strict=True, private_allowlist=("192.168.1.0/24",))
    assert resolve_targets(["192.168.1.9"], ScanProfile.DISCOVERY, policy)[1] == 1
    assert code(["192.168.2.9"], policy) == "out_of_scope"
    assert code(["10.0.0.5"], policy) == "out_of_scope"


def test_exclusions_win_and_reject_partially_overlapping_ranges():
    policy = state(exclusions=("192.168.1.10", "192.168.1.128/25"))
    assert code(["192.168.1.10"], policy) == "excluded_target"
    assert code(["192.168.1.0/24"], policy) == "excluded_target"      # overlaps, not carved up
    assert code(["192.168.1.200"], policy) == "excluded_target"
    assert resolve_targets(["192.168.1.16/28"], ScanProfile.DISCOVERY, policy)[1] == 14


def test_exclusion_beats_an_explicit_allowlist_entry():
    policy = state(
        private_strict=True, private_allowlist=("192.168.1.0/24",),
        exclusions=("192.168.1.0/30",),
    )
    assert code(["192.168.1.1"], policy) == "excluded_target"


def test_public_is_off_by_default_and_toggle_alone_authorizes_nothing():
    assert code(["8.8.8.8"]) == "public_address"
    assert code(["8.8.8.8"], state(public_enabled=True)) == "public_not_allowlisted"
    ok = state(public_enabled=True, public_allowlist=("8.8.8.0/24",))
    assert resolve_targets(["8.8.8.8"], ScanProfile.DISCOVERY, ok)[1] == 1
    assert code(["8.8.4.4"], ok) == "public_not_allowlisted"
    assert code(["8.8.8.0/23"], ok) == "public_not_allowlisted"   # only partly listed
    # Disabling revokes immediately.
    assert code(["8.8.8.8"], state(public_allowlist=("8.8.8.0/24",))) == "public_address"


def test_public_targets_are_limited_to_non_intrusive_profiles(monkeypatch):
    monkeypatch.setattr(settings, "scan_security_profile_enabled", True)
    ok = state(public_enabled=True, public_allowlist=("8.8.8.0/24",))
    assert code(["8.8.8.8"], ok, ScanProfile.SECURITY) == "profile_not_allowed_for_public"
    assert resolve_targets(["8.8.8.8"], ScanProfile.PORTS, ok)[1] == 1


def test_mixed_private_and_public_request_fails_as_a_whole():
    ok = state(public_enabled=True, public_allowlist=("8.8.8.0/24",))
    resolve_targets(["8.8.8.8"], ScanProfile.DISCOVERY, ok)
    assert code(["192.168.1.5", "8.8.4.4"], ok) == "public_not_allowlisted"


def test_security_profile_authorization_is_not_broadened_by_policy():
    from app.scan_scope import check_profile_enabled

    with pytest.raises(ScopeError) as err:
        check_profile_enabled(ScanProfile.SECURITY)
    assert err.value.code == "profile_disabled"


# ------------------------------------------------- deployment ceiling rules

def test_environment_ceiling_is_immutable_for_runtime_policy(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "192.168.1.0/24")
    policy = state(private_strict=True, private_allowlist=("192.168.1.0/25",))
    assert resolve_targets(["192.168.1.5"], ScanProfile.DISCOVERY, policy)[1] == 1
    assert code(["10.0.0.5"], state()) == "out_of_scope"
    assert code(["192.168.2.5"], state()) == "out_of_scope"
    with pytest.raises(scan_policy.PolicyValidationError) as err:
        scan_policy.check_against_ceiling(
            ["10.0.0.0/24"], [], scan_policy.deployment_ceiling()
        )
    assert err.value.code == "outside_deployment_ceiling"


def test_explicit_env_false_blocks_public_even_when_runtime_enables_it(monkeypatch):
    monkeypatch.setattr(settings, "scan_allow_public_env", False)
    ok = state(public_enabled=True, public_allowlist=("8.8.8.0/24",))
    assert code(["8.8.8.8"], ok) == "public_address"


def test_env_true_does_not_authorize_public_by_itself(monkeypatch):
    monkeypatch.setattr(settings, "scan_allow_public_env", True)
    assert code(["8.8.8.8"], state()) == "public_address"


def test_env_ceiling_applies_to_public_targets_too(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "192.168.1.0/24")
    ok = state(public_enabled=True, public_allowlist=("8.8.8.0/24",))
    assert code(["8.8.8.8"], ok) == "out_of_scope"


def test_effective_view_intersects_policy_with_ceiling(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "192.168.0.0/16, 10.1.0.0/16")
    view = scan_policy.effective_view(
        state(private_strict=True, private_allowlist=("192.168.5.0/24", "172.16.0.0/24")),
        scan_policy.deployment_ceiling(),
    )
    assert view["private_networks"] == ["192.168.5.0/24"]
    assert view["private_scanning"] is True
    assert view["public_scanning"] is False


# ------------------------------------------------------- fail-closed loading

def test_invalid_or_unreadable_environment_never_widens(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "garbage")
    assert code(["10.0.0.1"]) == "no_scope_configured"


def test_missing_policy_row_fails_closed_in_production(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    with SessionLocal() as db:
        with pytest.raises(scan_policy.PolicyUnavailable) as err:
            scan_policy.load_policy(db)
    assert err.value.code == "policy_missing"
    # ...and scanning is denied rather than defaulting to "allowed".
    assert code(["10.0.0.1"], policy=None) == "policy_missing"


def test_corrupt_stored_policy_fails_closed():
    from app.models import ScanPolicy

    with SessionLocal() as db:
        scan_policy.load_policy(db)  # seeds in non-production
        db.query(ScanPolicy).update({"private_allowlist": {"v": ["8.8.8.0/24"]}})
        db.commit()
        with pytest.raises(scan_policy.PolicyUnavailable) as err:
            scan_policy.load_policy(db)
    assert err.value.code == "policy_invalid"
    assert code(["10.0.0.1"], policy=None) == "policy_invalid"


def test_database_error_is_unavailable_not_permissive(monkeypatch):
    from sqlalchemy.exc import OperationalError

    class Boom:
        def scalars(self, *_a, **_k):
            raise OperationalError("select", {}, Exception("db down"))

        def rollback(self):
            pass

    with pytest.raises(scan_policy.PolicyUnavailable) as err:
        scan_policy.load_policy(Boom())  # type: ignore[arg-type]
    assert err.value.transient and err.value.code == "policy_unavailable"


# ------------------------------------------------------------ normalization

@pytest.mark.parametrize("field,value,expected", [
    ("private_allowlist", ["8.8.8.0/24"], "not_rfc1918"),
    ("private_allowlist", ["10.0.0.0/7"], "not_rfc1918"),     # spills into 11.0.0.0/8
    ("private_allowlist", ["10.1.2.3/8"], "invalid_cidr"),    # host bits: never widened silently
    ("private_allowlist", ["10.0.0.0/8", "10.0.0.0/8"], "duplicate_entry"),
    ("private_allowlist", ["127.0.0.0/8"], "not_rfc1918"),
    ("private_allowlist", ["example.com"], "invalid_cidr"),
    ("private_allowlist", ["::1"], "invalid_cidr"),
    ("private_allowlist", [5], "invalid_cidr"),
    ("private_allowlist", "10.0.0.0/8", "invalid_list"),
    ("private_allowlist", ["10.0.0.0/8"] * 65, "too_many_entries"),
    ("public_allowlist", ["10.0.0.0/8"], "not_public"),
    ("public_allowlist", ["169.254.169.254"], "not_public"),
    ("public_allowlist", ["100.64.0.0/10"], "not_public"),
    ("public_allowlist", ["8.0.0.0/8"], "public_range_too_wide"),
    ("public_allowlist", ["0.0.0.0/0"], "not_public"),
    ("exclusions", ["bad"], "invalid_cidr"),
])
def test_policy_input_validation(field, value, expected):
    args = {"private_allowlist": [], "public_allowlist": [], "exclusions": []}
    args[field] = value
    with pytest.raises(scan_policy.PolicyValidationError) as err:
        scan_policy.normalize_config(**args)
    assert err.value.code == expected


def test_normalization_canonicalizes_single_addresses():
    private, public, excl = scan_policy.normalize_config(
        private_allowlist=["192.168.1.0/24"], public_allowlist=["8.8.8.8"],
        exclusions=["10.0.0.5"],
    )
    assert (private, public, excl) == (("192.168.1.0/24",), ("8.8.8.8/32",), ("10.0.0.5/32",))


# ----------------------------------------------------------- update service

def test_update_requires_current_revision_and_bumps_it():
    with SessionLocal() as db:
        current = scan_policy.load_policy(db)
        new = set_policy(db, private_strict=True, private_allowlist=["192.168.1.0/24"])
        assert new.revision == current.revision + 1
        with pytest.raises(scan_policy.PolicyConflict) as err:
            scan_policy.update_policy(
                db, actor="a", expected_revision=current.revision,
                **{**new.config(), "private_enabled": False},
            )
        assert err.value.current.revision == new.revision


def test_broadening_requires_confirmation_and_public_needs_its_own():
    with SessionLocal() as db:
        base = scan_policy.load_policy(db)
        cfg = {**base.config(), "public_enabled": True, "public_allowlist": ["8.8.8.0/24"]}
        with pytest.raises(scan_policy.PolicyConfirmationRequired) as err:
            scan_policy.update_policy(db, actor="a", expected_revision=1, **cfg)
        assert "public_enabled" in err.value.reasons and err.value.public
        with pytest.raises(scan_policy.PolicyConfirmationRequired):
            scan_policy.update_policy(
                db, actor="a", expected_revision=1, confirm_broadening=True, **cfg
            )
        done = scan_policy.update_policy(
            db, actor="a", expected_revision=1, confirm_broadening=True,
            confirm_public=True, **cfg,
        )
        assert done.public_enabled and done.revision == 2


def test_narrowing_needs_no_confirmation_but_removing_an_exclusion_does():
    with SessionLocal() as db:
        s = set_policy(db, exclusions=["192.168.1.5/32"])
        cfg = {**s.config(), "exclusions": []}
        with pytest.raises(scan_policy.PolicyConfirmationRequired) as err:
            scan_policy.update_policy(db, actor="a", expected_revision=s.revision, **cfg)
        assert err.value.reasons == ["exclusion_removed"]
        narrowed = scan_policy.update_policy(
            db, actor="a", expected_revision=s.revision, **{**s.config(), "private_enabled": False}
        )
        assert narrowed.private_enabled is False


def test_leaving_strict_mode_is_broadening_but_emptying_a_strict_list_is_not():
    with SessionLocal() as db:
        s = set_policy(db, private_strict=True, private_allowlist=["192.168.1.0/24"])
        # strict + populated -> strict + empty authorizes nothing: narrowing.
        emptied = scan_policy.update_policy(
            db, actor="a", expected_revision=s.revision,
            **{**s.config(), "private_allowlist": []},
        )
        assert emptied.private_strict and emptied.private_allowlist == ()
        # strict -> non-strict means "all RFC1918": needs confirmation.
        cfg = {**emptied.config(), "private_strict": False}
        with pytest.raises(scan_policy.PolicyConfirmationRequired) as err:
            scan_policy.update_policy(db, actor="a", expected_revision=emptied.revision, **cfg)
        assert err.value.reasons == ["private_strict_disabled"]
        # widening the listed ranges while strict also needs confirmation.
        s2 = set_policy(db, private_allowlist=["192.168.1.0/24"])
        with pytest.raises(scan_policy.PolicyConfirmationRequired) as widen:
            scan_policy.update_policy(
                db, actor="a", expected_revision=s2.revision,
                **{**s2.config(), "private_allowlist": ["192.168.0.0/16"]},
            )
        assert widen.value.reasons == ["private_allowlist_widened"]


def test_env_false_prevents_enabling_public_at_runtime(monkeypatch):
    monkeypatch.setattr(settings, "scan_allow_public_env", False)
    with SessionLocal() as db:
        cfg = {**scan_policy.load_policy(db).config(), "public_enabled": True}
        with pytest.raises(scan_policy.PolicyValidationError) as err:
            scan_policy.update_policy(
                db, actor="a", expected_revision=1, confirm_broadening=True,
                confirm_public=True, **cfg,
            )
    assert err.value.code == "public_blocked_by_deployment"


def test_update_and_audit_are_atomic():
    from app.models import ScanPolicy, ScanPolicyAudit

    def explode(_db, _new):
        raise RuntimeError("simulated failure inside the transaction")

    with SessionLocal() as db:
        current = scan_policy.load_policy(db)
        with pytest.raises(RuntimeError):
            scan_policy.update_policy(
                db, actor="a", expected_revision=current.revision,
                **{**current.config(), "private_enabled": False}, in_transaction=explode,
            )
        db.rollback()
        assert scan_policy.load_policy(db).revision == current.revision
        assert scan_policy.load_policy(db).private_enabled is True
        assert db.query(ScanPolicyAudit).count() == 0
        assert db.query(ScanPolicy).count() == 1


def test_unchanged_update_does_not_churn_revision():
    with SessionLocal() as db:
        cur = scan_policy.load_policy(db)
        same = scan_policy.update_policy(db, actor="a", expected_revision=cur.revision,
                                         **cur.config())
        assert same.revision == cur.revision


@pytest.mark.parametrize("target", [
    "192.168.1.8",
    "192.168.1.9",
    "192.168.1.10",
    "192.168.1.11",
])
def test_strict_allowlist_boundaries_are_valid_host_targets(target):
    """Authorization ranges do not define physical subnet boundaries."""
    policy = state(
        private_strict=True,
        private_allowlist=("192.168.1.8/30",),
    )
    assert resolve_targets([target], ScanProfile.DISCOVERY, policy)[1] == 1


@pytest.mark.parametrize("target", [
    "192.168.1.0",
    "192.168.1.127",
])
def test_deployment_ceiling_boundaries_are_valid_host_targets(monkeypatch, target):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "192.168.1.0/25")
    assert resolve_targets([target], ScanProfile.DISCOVERY, state())[1] == 1


def test_authorization_boundary_fix_preserves_denials():
    policy = state(
        private_strict=True,
        private_allowlist=("192.168.1.8/30",),
        exclusions=("192.168.1.11/32",),
    )
    assert code(["192.168.1.7"], policy) == "out_of_scope"
    assert code(["192.168.1.12"], policy) == "out_of_scope"
    assert code(["192.168.1.11"], policy) == "excluded_target"


def test_authorization_boundary_fix_preserves_deployment_ceiling(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_cidrs_raw", "192.168.1.0/25")
    assert code(["192.168.1.128"]) == "out_of_scope"
