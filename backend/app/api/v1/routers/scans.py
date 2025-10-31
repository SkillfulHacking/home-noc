# backend/app/api/v1/routers/scans.py
from fastapi import APIRouter, Depends, Query
from typing import List
from ....security import require_api_key

router = APIRouter(prefix="/scans", tags=["scans"])

@router.post("/ping-sweep", dependencies=[Depends(require_api_key)])
def ping_sweep(targets: List[str] = Query(...), dry_run: bool = True):
    """
    Non-intrusive ping sweep (dry-run by default).
    Legal note: Only scan assets you own or have explicit permission to test.
    """
    # Placeholder: just echo sanitized targets when dry_run
    if dry_run:
        return {"mode": "dry-run", "targets": targets, "cmd_example": f"fping -a {' '.join(targets)}"}
    # Intentionally not executing external commands by default
    return {"mode": "exec", "executed": False, "reason": "Execution disabled by default"}
