# backend/app/api/v1/routers/scans.py
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ....security import require_api_key

router = APIRouter(prefix="/scans", tags=["scans"])

Targets = Annotated[
    list[str],
    Query(..., description="Targets to ping (e.g., hostnames or 192.168.1.0/24)"),
]


@router.post("/ping-sweep", dependencies=[Depends(require_api_key)])
def ping_sweep(targets: Targets, dry_run: bool = True):
    """
    Non-intrusive ping sweep (dry-run by default).
    """
    # Placeholder: just echo sanitized targets when dry_run
    if dry_run:
        return {
            "mode": "dry-run",
            "targets": targets,
            "cmd_example": f"fping -a {' '.join(targets)}",
        }
    # Intentionally not executing external commands by default
    return {"mode": "exec", "executed": False, "reason": "Execution disabled by default"}
