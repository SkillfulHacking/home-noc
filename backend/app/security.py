# backend/app/security.py
from fastapi import Header, HTTPException, status
from .config import settings

async def require_api_key(x_api_key: str | None = Header(default=None)):
    # If API_KEY is defined, enforce it for write operations via dependency injection
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
