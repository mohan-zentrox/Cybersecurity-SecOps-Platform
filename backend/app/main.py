"""
Project Aegis — FastAPI application entrypoint.

Defensive/internal SOC tooling: event ingestion & ECS normalization,
detection rule evaluation, alerting, case management, and a tamper-evident
audit trail. See docs/ARCHITECTURE.md for the system overview.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import alerts, audit, auth, cases, events, rules
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import engine

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Dev convenience only. Production schema changes are managed exclusively
    # through Alembic migrations (backend/alembic/) — see docs/ARCHITECTURE.md.
    if settings.ENV == "development":
        Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Cybersecurity SecOps platform: ingestion, detection, alerting, case management, audit.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS: permissive defaults for local dev only. Lock this down to explicit
# origins before any non-local deployment (see docs/THREAT_MODEL.md).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(events.router, prefix=settings.API_V1_PREFIX)
app.include_router(rules.router, prefix=settings.API_V1_PREFIX)
app.include_router(alerts.router, prefix=settings.API_V1_PREFIX)
app.include_router(cases.router, prefix=settings.API_V1_PREFIX)
app.include_router(audit.router, prefix=settings.API_V1_PREFIX)


@app.get("/healthz", tags=["health"])
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": settings.PROJECT_NAME}
