# backend/app/api/v1/routers/auth.py
"""Administrator login/logout/session endpoints (M03, issue #6)."""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .... import auth as auth_service
from ....dependencies import get_db
from ....security import (
    SESSION_COOKIE_NAME,
    SessionDep,
    clear_session_cookies,
    set_session_cookies,
)

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)

DbDep = Annotated[Session, Depends(get_db)]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    # Bounded so a pathological input cannot turn PBKDF2 into a CPU DoS.
    password: str = Field(min_length=1, max_length=1024)


class SessionResponse(BaseModel):
    username: str
    expires_at: str


@router.post("/login", response_model=SessionResponse)
def login(payload: LoginRequest, response: Response, db: DbDep):
    """Exchange operator credentials for a server-side session.

    Failures are deliberately indistinguishable from one another: the same
    401 and the same message cover an unknown user, a wrong password and an
    unconfigured deployment, so the response cannot be used to enumerate.
    """
    locked_for = auth_service.login_lockout_remaining(payload.username)
    if locked_for:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed sign-in attempts; try again later",
            headers={"Retry-After": str(locked_for)},
        )

    if not auth_service.authenticate(payload.username, payload.password):
        auth_service.record_failed_attempt(payload.username)
        # Username only -- never the submitted password or any part of it.
        logger.warning("Failed admin sign-in attempt for username %r", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    auth_service.reset_failed_attempts(payload.username)
    issued = auth_service.create_session(db, payload.username)
    set_session_cookies(response, issued)
    return SessionResponse(
        username=payload.username, expires_at=issued.expires_at.isoformat()
    )


@router.get("/session", response_model=SessionResponse)
def read_session(session: SessionDep):
    """The protected route the SPA probes to confirm it is really signed in."""
    return SessionResponse(
        username=session.username, expires_at=session.expires_at.isoformat()
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: DbDep, session: SessionDep):
    """Revoke the server-side session, then clear the client's cookies.

    ``session`` is required (and CSRF-checked) so logout cannot be triggered
    cross-site, and the row is deleted so the token is dead even if the
    cookie survives on the client.
    """
    auth_service.revoke_session(db, request.cookies.get(SESSION_COOKIE_NAME))
    # Mutate the injected Response so FastAPI merges the Set-Cookie headers
    # into the 204; returning a fresh Response here would drop them.
    clear_session_cookies(response)
    return None
