# app/db.py
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import settings

Base = declarative_base()

def _make_engine(url: str):
    kwargs = {"future": True}
    if url.startswith("sqlite://"):
        # sqlite needs this to allow usage across threads (TestClient, etc.)
        kwargs["connect_args"] = {"check_same_thread": False}

        # If using an in-memory DB, ensure a single shared connection
        if url.endswith(":memory:"):
            kwargs["poolclass"] = StaticPool

    return create_engine(url, **kwargs)

engine = _make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
