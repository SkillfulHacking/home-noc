# backend/app/security.py
"""Request-level authentication and CSRF enforcement (M03, issue #6).

Every inventory read, inventory mutation and scan route depends on
``require_session``. There is no anonymous path and no shared-key bypass:
an unauthenticated request is a 401 in every environment, including dev.
"""
from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from . import auth
from .config import settings
from .dependencies import get_db

SESSION_COOKIE_NAME = "home_noc_session"
CSRF_COOKIE_NAME = "home_noc_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"

# Methods that cannot change state, so a forged cross-site request gains
# nothing by issuing them.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Authentication required",
    headers={"WWW-Authenticate": "Cookie"},
)


def set_session_cookies(response, issued: auth.IssuedSession) -> None:
    """Attach the session and CSRF cookies for a freshly issued session."""
    max_age = settings.session_ttl_seconds
    secure = settings.session_cookie_secure
    response.set_cookie(
        SESSION_COOKIE_NAME,
        issued.session_token,
        max_age=max_age,
        httponly=True,       # unreadable from JavaScript, so XSS cannot exfiltrate it
        secure=secure,
        samesite="strict",   # browsers will not attach it to cross-site requests
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        issued.csrf_token,
        max_age=max_age,
        httponly=False,      # the SPA must read this to echo it back in a header
        secure=secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookies(response) -> None:
    for name in (SESSION_COOKIE_NAME, CSRF_COOKIE_NAME):
        response.delete_cookie(
            name,
            path="/",
            httponly=name == SESSION_COOKIE_NAME,
            secure=settings.session_cookie_secure,
            samesite="strict",
        )


async def require_session(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
    csrf_header: Annotated[str | None, Header(alias=CSRF_HEADER_NAME)] = None,
) -> auth.AuthenticatedSession:
    """Authenticate the caller and, for unsafe methods, enforce CSRF.

    The CSRF check is a double-submit against the *stored digest* of the
    token rather than against the cookie value, so an attacker who can set
    a cookie (but not read the response) still cannot forge a matching pair.
    """
    session = auth.resolve_session(db, session_cookie)
    if session is None:
        raise _UNAUTHENTICATED

    if request.method.upper() not in SAFE_METHODS:
        if not csrf_header or not hmac.compare_digest(
            auth.hash_token(csrf_header), session.csrf_hash
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing or invalid CSRF token",
            )
    return session


SessionDep = Annotated[auth.AuthenticatedSession, Depends(require_session)]
AUTH_DEP = [Depends(require_session)]
