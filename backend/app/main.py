"""
Project Aegis — FastAPI application entrypoint.

Defensive/internal SOC tooling: event ingestion & ECS normalization,
threat-intel enrichment, detection rule evaluation, alerting with real
notification delivery, case management with SLA enforcement, vulnerability
management, compliance reporting, and a tamper-evident audit trail.
See docs/ARCHITECTURE.md for the system overview.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.v1 import (
    alerts,
    audit,
    auth,
    cases,
    compliance,
    events,
    kpis,
    notifications,
    rules,
    threat_intel,
    users,
    vulnerabilities,
)
from app.core.config import get_settings
from app.core.logging import RequestContextMiddleware, configure_logging
from app.db.base import Base
from app.db.session import engine
from app.services.scheduler import scheduler

settings = get_settings()
configure_logging(settings.LOG_LEVEL, settings.LOG_JSON)
log = logging.getLogger("aegis.main")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Refuse to boot in production with development placeholders in place.
    problems = settings.validate_runtime()
    if problems:
        for problem in problems:
            log.critical("fatal configuration error", extra={"aegis.problem": problem})
        raise RuntimeError(f"Unsafe production configuration: {'; '.join(problems)}")

    # Dev convenience only. Production schema changes are managed exclusively
    # through Alembic migrations (backend/alembic/) — see docs/ARCHITECTURE.md.
    if settings.ENV == "development":
        Base.metadata.create_all(bind=engine)

    scheduler.start()
    log.info("application started", extra={"aegis.env": settings.ENV, "aegis.ingest_mode": settings.INGEST_MODE})
    try:
        yield
    finally:
        await scheduler.stop()
        log.info("application stopped")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Cybersecurity SecOps platform: ingestion, enrichment, detection, alerting, "
        "case management, vulnerability management, compliance reporting, and audit."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(RequestContextMiddleware)

# Locked to the configured origin list; CORS_ORIGINS must not be '*' in
# production (enforced by Settings.validate_runtime) — see docs/THREAT_MODEL.md.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

for router in (
    auth.router,
    users.router,
    events.router,
    rules.router,
    alerts.router,
    cases.router,
    threat_intel.router,
    vulnerabilities.router,
    compliance.router,
    notifications.router,
    kpis.router,
    audit.router,
):
    app.include_router(router, prefix=settings.API_V1_PREFIX)


@app.get("/healthz", tags=["health"])
def healthz() -> dict[str, str]:
    """Liveness: the process is up. Never touches dependencies."""
    return {"status": "ok", "service": settings.PROJECT_NAME}


@app.get("/readyz", tags=["health"])
def readyz(response: Response) -> dict[str, object]:
    """Readiness: dependencies are actually reachable.

    A liveness probe that returns 200 while the database is unreachable will
    happily route traffic into a broken replica, so the checks are separate.
    """
    checks: dict[str, str] = {}

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001 - report the failure, do not raise
        checks["database"] = f"error: {exc}"[:200]

    if settings.QUEUE_BACKEND == "redis":
        try:
            import redis

            redis.Redis.from_url(settings.REDIS_URL).ping()
            checks["queue"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["queue"] = f"error: {exc}"[:200]
    else:
        checks["queue"] = "ok (in-memory)"

    ready = all(value.startswith("ok") for value in checks.values())
    if not ready:
        # 503 so an orchestrator actually takes the replica out of rotation;
        # a 200 "degraded" body would keep routing traffic into a broken pod.
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready else "degraded", "checks": checks}
