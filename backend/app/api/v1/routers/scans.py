# backend/app/api/v1/routers/scans.py
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from ....config import settings
from ....scan_scope import (
    PROFILES,
    ScanProfile,
    ScopeError,
    allowed_networks,
    check_profile_enabled,
    log_authorization,
    resolve_targets,
)
from ....security import SessionDep

router = APIRouter(prefix="/scans", tags=["scans"])

Targets = Annotated[
    list[str],
    Query(..., description="IPv4 addresses or CIDRs inside the authorized scan scope"),
]

_FORBIDDEN_CODES = {
    "out_of_scope", "public_address", "target_forbidden",
    "no_scope_configured", "profile_disabled",
}


class PreflightRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # no free-form scanner flags

    targets: list[str] = Field(min_length=1, max_length=64)
    profile: ScanProfile = ScanProfile.DISCOVERY


def _preflight(targets: list[str], profile: ScanProfile, session, dry_run: bool) -> dict:
    try:
        check_profile_enabled(profile)
        networks, count = resolve_targets(targets, profile)
    except ScopeError as exc:
        # Log the rejection reason code only; never echo raw operator input.
        log_authorization(
            operator=session.username, profile=profile, networks=[], count=0,
            dry_run=dry_run, outcome=f"rejected:{exc.code}",
        )
        status = 403 if exc.code in _FORBIDDEN_CODES else 422
        raise HTTPException(
            status_code=status, detail={"code": exc.code, "message": exc.message}
        ) from None
    log_authorization(
        operator=session.username, profile=profile, networks=networks, count=count,
        dry_run=dry_run, outcome="approved",
    )
    spec = PROFILES[profile]
    return {
        "approved": True,
        "mode": "dry-run" if dry_run else "exec",
        "profile": profile.value,
        "intrusive": spec.intrusive,
        "resolved_targets": [str(n) for n in networks],
        "resolved_target_count": count,
        "limits": {
            "max_hosts": spec.max_hosts,
            "timeout_seconds": spec.timeout_seconds,
            "max_concurrency": spec.max_concurrency,
        },
    }


@router.get("/scope")
def scope(session: SessionDep):
    """Configured authorization scope and profiles, for the UI."""
    return {
        "allowed_cidrs": [str(n) for n in allowed_networks()],
        "allow_public": settings.scan_allow_public,
        "profiles": [
            {
                "name": p.name.value,
                "description": p.description,
                "intrusive": p.intrusive,
                "enabled": (not p.intrusive) or settings.scan_security_profile_enabled,
                "max_hosts": p.max_hosts,
            }
            for p in PROFILES.values()
        ],
    }


@router.post("/preflight")
def preflight(body: PreflightRequest, session: SessionDep):
    """Validate targets/profile against the authorized scope (dry run)."""
    return _preflight(body.targets, body.profile, session, dry_run=True)


@router.post("/ping-sweep")
def ping_sweep(
    targets: Targets,
    session: SessionDep,
    dry_run: bool = True,
):
    """Discovery-profile ping sweep. Scope is validated in every mode."""
    result = _preflight(targets, ScanProfile.DISCOVERY, session, dry_run)
    if dry_run:
        return result
    # Intentionally not executing external commands by default.
    result["executed"] = False
    result["reason"] = "Execution disabled by default"
    return result
