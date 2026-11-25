# backend/app/api/v1/routers/scan_policy.py
"""Administrator scan policy settings (M08A, issue #66).

Admin-only. Reads are session-authenticated; writes also require the CSRF
header (enforced by ``require_session``). Responses carry operational policy
only -- no secrets and no unrelated environment values.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .... import jobs, scan_policy
from ....config import settings
from ....dependencies import get_db
from ....models import ScanPolicyAudit
from ....scan_scope import MAX_TARGET_ENTRIES, PROFILES
from ....security import AdminDep

router = APIRouter(prefix="/scan-policy", tags=["scan-policy"])

DbDep = Annotated[Session, Depends(get_db)]

WORKER_VANTAGE = (
    "Scans run from the worker container's network position (its Docker network and "
    "routes), which may not match the browser's or the host's. A target reachable "
    "from your workstation can still be unreachable from the worker."
)


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1, description="Revision this edit is based on")
    private_enabled: bool
    private_allowlist: list[str] = Field(
        default_factory=list, max_length=scan_policy.MAX_POLICY_ENTRIES
    )
    public_enabled: bool = False
    public_allowlist: list[str] = Field(
        default_factory=list, max_length=scan_policy.MAX_POLICY_ENTRIES
    )
    exclusions: list[str] = Field(default_factory=list, max_length=scan_policy.MAX_EXCLUSIONS)
    confirm_broadening: bool = Field(
        default=False, description="Acknowledges that this change authorizes more scanning"
    )
    confirm_public: bool = Field(
        default=False, description="Acknowledges the public-address ownership warning"
    )


def policy_view(state: scan_policy.PolicyState) -> dict:
    ceiling = scan_policy.deployment_ceiling()
    return {
        "revision": state.revision,
        "updated_at": state.updated_at,
        "updated_by": state.updated_by,
        "bootstrap_origin": state.bootstrap_origin,
        "private": {
            "enabled": state.private_enabled,
            "allowlist": list(state.private_allowlist),
            "rfc1918": [str(n) for n in scan_policy.RFC1918],
        },
        "public": {
            "enabled": state.public_enabled,
            "allowlist": list(state.public_allowlist),
            "min_prefix": scan_policy.MIN_PUBLIC_PREFIX,
        },
        "exclusions": list(state.exclusions),
        "effective": scan_policy.effective_view(state, ceiling),
        "deployment": {
            "scope_restricted": ceiling.restricted,
            "allowed_cidrs": [str(n) for n in ceiling.networks],
            "public_blocked": ceiling.public_blocked,
            "security_profile_enabled": settings.scan_security_profile_enabled,
        },
        "limits": {
            "max_target_entries": MAX_TARGET_ENTRIES,
            "max_policy_entries": scan_policy.MAX_POLICY_ENTRIES,
            "max_exclusions": scan_policy.MAX_EXCLUSIONS,
            "min_public_prefix": scan_policy.MIN_PUBLIC_PREFIX,
            "max_active_jobs": settings.scan_max_active_jobs,
            "profiles": [
                {
                    "name": p.name.value, "intrusive": p.intrusive, "max_hosts": p.max_hosts,
                    "timeout_seconds": p.timeout_seconds, "max_concurrency": p.max_concurrency,
                }
                for p in PROFILES.values()
            ],
        },
        "worker_vantage": WORKER_VANTAGE,
    }


def _unavailable(exc: scan_policy.PolicyUnavailable) -> HTTPException:
    return HTTPException(status_code=503, detail={"code": exc.code, "message": exc.message})


_COMMON_ERRORS: dict[int | str, dict] = {
    401: {"description": "Not authenticated"},
    403: {"description": "Not the administrator (`admin_required`) or missing CSRF token"},
    503: {
        "description": "Stored policy missing/invalid/unreadable (`policy_missing`, "
        "`policy_invalid`, `policy_unavailable`); all scanning is denied meanwhile",
    },
}


@router.get(
    "",
    summary="Read the runtime scan policy",
    description="Administrator only. Returns the stored policy, the effective (authorized "
    "right now) view, immutable deployment restrictions, limits and the revision.",
    responses=_COMMON_ERRORS,
)
def read_policy(admin: AdminDep, db: DbDep):
    try:
        return policy_view(scan_policy.load_policy(db))
    except scan_policy.PolicyUnavailable as exc:
        raise _unavailable(exc) from None


@router.put(
    "",
    summary="Replace the runtime scan policy",
    description="Administrator only; requires the CSRF header. Validated and applied "
    "atomically with its audit row, guarded by `expected_revision`. Broadening requires "
    "`confirm_broadening` (and `confirm_public` for public ranges). Takes effect without a "
    "restart; queued jobs it no longer authorizes fail, running jobs are stopped by the worker.",
    responses={
        **_COMMON_ERRORS,
        409: {"description": "`revision_conflict` (includes `current`) or `confirmation_required`"},
        422: {"description": "Invalid policy: `{code, message, field}`"},
    },
)
def write_policy(body: PolicyUpdate, admin: AdminDep, db: DbDep):
    submitted = body.model_dump(exclude={"expected_revision"})
    try:
        state = scan_policy.update_policy(
            db,
            actor=admin.username,
            expected_revision=body.expected_revision,
            private_enabled=body.private_enabled,
            private_allowlist=body.private_allowlist,
            public_enabled=body.public_enabled,
            public_allowlist=body.public_allowlist,
            exclusions=body.exclusions,
            confirm_broadening=body.confirm_broadening,
            confirm_public=body.confirm_public,
            # Queued jobs the new policy no longer authorizes fail in the same
            # transaction; running jobs are stopped by their worker.
            in_transaction=lambda session, new: jobs.fail_unauthorized_queued(session, new),
        )
    except scan_policy.PolicyValidationError as exc:
        scan_policy.record_rejection(
            db, actor=admin.username, outcome=f"rejected:{exc.code}", submitted=submitted
        )
        raise HTTPException(
            status_code=422,
            detail={"code": exc.code, "message": exc.message, "field": exc.field},
        ) from None
    except scan_policy.PolicyConflict as exc:
        scan_policy.record_rejection(
            db, actor=admin.username, outcome="rejected:revision_conflict", submitted=submitted
        )
        raise HTTPException(
            status_code=409,
            detail={
                "code": "revision_conflict",
                "message": "The policy was changed by someone else; review the current "
                           "policy and re-apply your edit",
                # HTTPException details are serialized by plain json: make it JSON-safe.
                "current": jsonable_encoder(policy_view(exc.current)),
            },
        ) from None
    except scan_policy.PolicyConfirmationRequired as exc:
        scan_policy.record_rejection(
            db, actor=admin.username, outcome="rejected:confirmation_required",
            submitted=submitted,
        )
        raise HTTPException(
            status_code=409,
            detail={
                "code": "confirmation_required",
                "message": "This change authorizes more scanning and must be confirmed",
                "reasons": exc.reasons,
                "public_confirmation_required": exc.public,
            },
        ) from None
    except scan_policy.PolicyUnavailable as exc:
        raise _unavailable(exc) from None
    return policy_view(state)


@router.get(
    "/audit",
    summary="Scan policy audit trail (newest first)",
    responses=_COMMON_ERRORS,
)
def read_audit(
    admin: AdminDep,
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
):
    rows = db.scalars(select(ScanPolicyAudit).order_by(ScanPolicyAudit.id.desc()).limit(limit))
    return {
        "items": [
            {
                "id": r.id, "at": r.at, "actor": r.actor, "outcome": r.outcome,
                "prior_revision": r.prior_revision, "new_revision": r.new_revision,
                "prior": r.prior, "new": r.new,
            }
            for r in rows
        ]
    }
