# backend/app/main.py
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sqlalchemy import text

from .config import settings
from .db import Base, engine
from . import models  # <-- ensure model classes are registered

from .api.v1.routers import devices, scans
from .version import APP_VERSION


def _ensure_schema():
    if settings.app_env in {"dev", "test"}:
        # safety import (noop if already imported)
        from . import models  # noqa: F401
        Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _ensure_schema()  # dev/test convenience
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
api_v1.include_router(devices.router)
api_v1.include_router(scans.router)
app.include_router(api_v1)

# <-- ensure schema AFTER routers are included, for environments that don't
# reliably execute lifespan during tests (older/newer TestClient differences).
_ensure_schema()


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"ok": True, "app": "home-noc"}


@app.get("/version")
def version():
    return {"version": APP_VERSION}
