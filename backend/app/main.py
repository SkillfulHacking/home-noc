# backend/app/main.py 
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sqlalchemy import text

from .config import settings
from .db import Base, engine
from .version import APP_VERSION
from .api.v1.routers import devices, scans


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Optional bootstrap (off by default; migrations handle schema)
    if os.getenv("AUTO_CREATE_TABLES", "0") == "1":
        Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Home-NOC API",
    version=APP_VERSION,
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

@app.get("/health", tags=["meta"])
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"ok": True, "app": settings.app_name, "version": APP_VERSION}

@app.get("/version", tags=["meta"])
def version():
    return {"version": APP_VERSION}

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(devices.router)
api_v1.include_router(scans.router)
app.include_router(api_v1)
