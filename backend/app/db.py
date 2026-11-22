# app/db.py
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import settings

Base = declarative_base()

def _make_engine(url: str):
    kwargs = {"future": True}
    is_sqlite = url.startswith("sqlite://")
    if is_sqlite:
        # sqlite needs this to allow usage across threads (TestClient, etc.)
        kwargs["connect_args"] = {"check_same_thread": False}

        # If using an in-memory DB, ensure a single shared connection
        if url.endswith(":memory:"):
            kwargs["poolclass"] = StaticPool

    engine = create_engine(url, **kwargs)

    if is_sqlite:
        # SQLite ignores FK constraints (e.g. ON DELETE CASCADE) unless
        # explicitly enabled per connection.
        @event.listens_for(engine, "connect")
        def _enable_sqlite_fk(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine

engine = _make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
