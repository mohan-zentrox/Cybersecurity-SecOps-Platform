"""
Database engine/session wiring.

FRD ref: FRD-DATA-01. `get_db` is the standard FastAPI dependency used by
every route module. Tests override this dependency (see
backend/tests/conftest.py) to point at an isolated in-memory SQLite engine
so the full API and service layer can be exercised without a live Postgres
instance.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

settings = get_settings()

_engine_kwargs: dict = {"future": True}
if settings.DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
    if ":memory:" in settings.DATABASE_URL:
        # A plain in-memory SQLite DB is per-connection; without a shared
        # StaticPool, each new Session would see an empty database. This
        # matters for tests (see backend/tests/conftest.py), which point
        # DATABASE_URL at sqlite:///:memory: for isolation and speed.
        _engine_kwargs["poolclass"] = StaticPool

engine = create_engine(settings.DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
