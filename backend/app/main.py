# backend/app/main.py
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sqlalchemy import text

from .api.v1.routers import devices, scans
from .config import settings
from .db import Base, engine
from .version import APP_VERSION


def _ensure_schema():
    if settings.app_env in {"dev", "test"}:
        Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In dev/test, ensure schema exists without Alembic
    _ensure_schema()
    yield


app = FastAPI(
    title="home-noc",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

# Also ensure schema at import time for environments/tests that don't run lifespan
_ensure_schema()

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


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"ok": True, "app": "home-noc"}


@app.get("/version")
def version():
    return {"version": APP_VERSION}
