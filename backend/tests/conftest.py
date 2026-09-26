"""
Pytest fixtures for Project Aegis.

Everything runs against an in-memory SQLite database (no live Postgres/
Redis required) so the full API and service layer can be exercised in
CI/offline. Environment variables MUST be set before any `app.*` module is
imported, since app.core.config.get_settings() is process-wide cached.
"""

import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("ENV", "test")
os.environ.setdefault("QUEUE_BACKEND", "memory")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-production")
os.environ.setdefault("SCHEDULER_ENABLED", "false")  # no background jobs under test
os.environ.setdefault("LOG_LEVEL", "WARNING")        # silence per-request access logs
os.environ.setdefault("LOG_JSON", "false")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.auth import _login_rate_limiter
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.main import app
from app.models.user import AppRole, User
from app.services.queue import reset_queue_for_tests


@pytest.fixture(autouse=True)
def _fresh_schema_and_state():
    """Reset the DB schema, in-process queue, and login rate limiter before every test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    reset_queue_for_tests()
    _login_rate_limiter.reset_all()
    yield


@pytest.fixture
def db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


DEFAULT_PASSWORD = "Str0ng-Passw0rd!"


def make_user(db: Session, *, username: str, role: str, password: str = DEFAULT_PASSWORD) -> User:
    user = User(
        username=username,
        email=f"{username}@example.test",
        hashed_password=hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def analyst_user(db) -> User:
    return make_user(db, username="analyst1", role=AppRole.ANALYST)


@pytest.fixture
def detection_engineer_user(db) -> User:
    return make_user(db, username="detengineer1", role=AppRole.DETECTION_ENGINEER)


@pytest.fixture
def compliance_user(db) -> User:
    return make_user(db, username="compliance1", role=AppRole.COMPLIANCE)


@pytest.fixture
def admin_user(db) -> User:
    return make_user(db, username="admin1", role=AppRole.ADMIN)


def auth_headers(client: TestClient, username: str, password: str = DEFAULT_PASSWORD) -> dict[str, str]:
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
