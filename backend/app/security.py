# backend/app/security.py
from __future__ import annotations

from fastapi import Header, HTTPException, status

from .config import settings


async def require_api_key(x_api_key: str | None = Header(default=None)):
    if settings.api_key:
        if x_api_key != settings.api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
    else:
        # API key not configured; access allowed. If you want to enforce API key presence, uncomment below:
        # raise HTTPException(
        #     status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        #     detail="API key not configured",
        # )
