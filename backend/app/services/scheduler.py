"""
In-process periodic job runner.

FRD ref: FRD-CASE-05 / FRD-TI-02 — two things must happen on a clock
rather than on a request: SLA deadlines have to be swept for breaches, and
threat-intel feeds have to be polled. Both are cheap and idempotent, so a
plain asyncio task started from the FastAPI lifespan is the right size of
tool here — no Celery/APScheduler dependency.

Each job gets its own DB session per tick (never a long-lived one), and an
exception in one tick is logged and swallowed so the loop survives a
transient database blip. For a horizontally-scaled deployment, run the
scheduler in exactly one replica (set ``SCHEDULER_ENABLED=false`` on the
others) or move these jobs behind a distributed lock.
"""

import asyncio
import logging
from collections.abc import Callable

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services.sla import sweep_sla_breaches
from app.services.threat_feeds import poll_all_enabled_feeds

log = logging.getLogger("aegis.scheduler")


def _run_sla_sweep() -> None:
    db = SessionLocal()
    try:
        result = sweep_sla_breaches(db)
        if result.total:
            log.info(
                "scheduled SLA sweep completed",
                extra={
                    "aegis.alerts_breached": len(result.alerts_breached),
                    "aegis.cases_breached": len(result.cases_breached),
                },
            )
    finally:
        db.close()


def _run_feed_poll() -> None:
    db = SessionLocal()
    try:
        results = poll_all_enabled_feeds(db)
        if results:
            log.info(
                "scheduled threat-intel poll completed",
                extra={
                    "aegis.feeds_polled": len(results),
                    "aegis.indicators_created": sum(r.created for r in results),
                },
            )
    finally:
        db.close()


async def _loop(name: str, interval_seconds: int, job: Callable[[], None]) -> None:
    log.info("scheduler job started", extra={"aegis.job": name, "aegis.interval_s": interval_seconds})
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            await asyncio.to_thread(job)
        except asyncio.CancelledError:
            log.info("scheduler job stopped", extra={"aegis.job": name})
            raise
        except Exception:  # noqa: BLE001 - a bad tick must not kill the loop
            log.exception("scheduler job tick failed", extra={"aegis.job": name})


class Scheduler:
    """Owns the background tasks; started and stopped by the app lifespan."""

    def __init__(self) -> None:
        self._tasks: list[asyncio.Task] = []

    def start(self) -> None:
        settings = get_settings()
        if not settings.SCHEDULER_ENABLED:
            log.info("scheduler disabled by configuration")
            return
        self._spawn("sla_sweep", settings.SLA_SWEEP_INTERVAL_SECONDS, _run_sla_sweep)
        self._spawn("threat_intel_poll", settings.THREAT_INTEL_POLL_INTERVAL_SECONDS, _run_feed_poll)

    def _spawn(self, name: str, interval: int, job: Callable[[], None]) -> None:
        self._tasks.append(asyncio.create_task(_loop(name, interval, job), name=f"aegis-{name}"))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - shutting down regardless
                pass
        self._tasks.clear()


scheduler = Scheduler()
