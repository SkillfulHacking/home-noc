# backend/app/security.py
from fastapi import Header, HTTPException, status
from .config import settings

async def require_api_key(x_api_key: str | None = Header(default=None)):
    # Enforce API key presence and validation in production
    if settings.app_env == 'prod':
        if not settings.api_key:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="API key not configured in production")
        if x_api_key != settings.api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    else:
        # In non-production, enforce API key only if defined
        if settings.api_key and x_api_key != settings.api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")