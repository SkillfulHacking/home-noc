# backend/app/main.py
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sqlalchemy import inspect, text

from .api.v1.routers import auth as auth_router
from .api.v1.routers import credentials as credentials_router
from .api.v1.routers import devices, scans
from .api.v1.routers import scan_policy as scan_policy_router
from .api.v1.routers import snmp as snmp_router
from .auth import validate_admin_configuration
from .config import settings
from .crypto import validate_credential_key_configuration
from .db import Base, engine
from .key_binding import verify_at_startup
from .version import APP_VERSION

# Fail closed at import time: a production deployment without a usable
# admin verifier must refuse to start rather than serve an open API.
validate_admin_configuration()
# A configured-but-unusable credential key also stops a production start.
validate_credential_key_configuration()


def _ensure_schema():
    if settings.app_env in {"dev", "test"}:
        # safety import (noop if already imported)
        from . import models  # noqa: F401
        Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _ensure_schema()  # dev/test convenience
    # A key that belongs to a different database stops a production start.
    verify_at_startup()
    yield


app = FastAPI(
    title="home-noc",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

# CORS
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# API v1
api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(auth_router.router)
api_v1.include_router(devices.router)
api_v1.include_router(scans.router)
api_v1.include_router(scan_policy_router.router)
api_v1.include_router(credentials_router.router)
api_v1.include_router(snmp_router.router)
app.include_router(api_v1)


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError):
    """FastAPI's default 422 body echoes the submitted ``input``. For the
    credential API that input is a secret, so only loc/msg/type are returned
    there. Every other route keeps the framework default."""
    if request.url.path.startswith("/api/v1/credentials"):
        safe = [
            {"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
            for e in exc.errors()
        ]
        return ORJSONResponse(status_code=422, content={"detail": safe})
    return await request_validation_exception_handler(request, exc)

# <-- ensure schema AFTER routers are included, for environments that don't
# reliably execute lifespan during tests (older/newer TestClient differences).
_ensure_schema()


@app.get("/health")
def health():
    """Liveness plus database readiness.

    Reports 503 (with a fixed, secret-free body) when the database is
    unreachable or the schema is incomplete, e.g. migrations failed or were
    never applied, so Compose never marks such a backend healthy.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            inspector = inspect(conn)
            missing = [
                name for name in Base.metadata.tables if not inspector.has_table(name)
            ]
    except Exception:  # noqa: BLE001 - never leak driver/path details
        return ORJSONResponse(
            status_code=503, content={"ok": False, "detail": "database unavailable"}
        )
    if missing:
        return ORJSONResponse(
            status_code=503,
            content={"ok": False, "detail": "database schema is not initialized"},
        )
    return {"ok": True, "app": "home-noc"}


@app.get("/version")
def version():
    return {"version": APP_VERSION}
