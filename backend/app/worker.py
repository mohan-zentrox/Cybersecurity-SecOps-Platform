"""
Standalone ingestion worker.

FRD ref: FRD-ING-03 — with ``INGEST_MODE=worker`` the API only enqueues
raw events; this process drains the queue, normalizes, enriches, persists,
and then runs the detection rules. That is what makes the queue load-
absorbing rather than decorative: an ingest spike grows the stream depth
instead of stretching request latency.

Run it with::

    python -m app.worker

Delivery is at-least-once. Messages are acknowledged only after the batch
has been durably written (see services/queue.py::RedisStreamQueue), and
entries orphaned by a crashed worker are reclaimed via XAUTOCLAIM on
startup and periodically thereafter.
"""

import logging
import signal
import sys
import time
from types import FrameType

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import SessionLocal
from app.services.normalizer import process_raw_batch
from app.services.queue import RedisStreamQueue, get_queue
from app.services.rule_engine import run_all_enabled_rules

log = logging.getLogger("aegis.worker")

RAW_EVENTS_TOPIC = "raw_events"

BATCH_SIZE = 500
IDLE_SLEEP_SECONDS = 1.0
RECLAIM_EVERY_SECONDS = 60
RECLAIM_MIN_IDLE_MS = 120_000

_shutdown = False


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    global _shutdown
    log.info("shutdown signal received", extra={"aegis.signal": signum})
    _shutdown = True


def _process(messages: list[dict]) -> int:
    """Normalize + enrich + persist a batch, then run detection. Returns alerts raised."""
    db = SessionLocal()
    try:
        summary = process_raw_batch(db, messages)
        alerts = run_all_enabled_rules(db) if summary.accepted else []
        log.info(
            "batch processed",
            extra={
                "aegis.accepted": summary.accepted,
                "aegis.dead_lettered": summary.dead_lettered,
                "aegis.threat_matches": summary.threat_matches,
                "aegis.alerts_created": len(alerts),
            },
        )
        return len(alerts)
    finally:
        db.close()


def run() -> int:
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL, settings.LOG_JSON)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    queue = get_queue()
    if not isinstance(queue, RedisStreamQueue):
        log.error(
            "worker requires QUEUE_BACKEND=redis; an in-memory queue is not shared across processes",
            extra={"aegis.queue_backend": settings.QUEUE_BACKEND},
        )
        return 2

    log.info(
        "ingestion worker started",
        extra={"aegis.topic": RAW_EVENTS_TOPIC, "aegis.consumer": settings.QUEUE_CONSUMER_NAME},
    )

    last_reclaim = 0.0
    while not _shutdown:
        try:
            # Periodically take over anything a dead worker left pending.
            if time.monotonic() - last_reclaim > RECLAIM_EVERY_SECONDS:
                reclaimed = queue.reclaim_stale(RAW_EVENTS_TOPIC, RECLAIM_MIN_IDLE_MS, BATCH_SIZE)
                last_reclaim = time.monotonic()
                if reclaimed:
                    log.warning("reclaimed orphaned messages", extra={"aegis.count": len(reclaimed)})
                    _process([m for _, m in reclaimed])
                    queue.ack_batch(RAW_EVENTS_TOPIC, [i for i, _ in reclaimed])

            batch = queue.read_batch(RAW_EVENTS_TOPIC, BATCH_SIZE)
            if not batch:
                time.sleep(IDLE_SLEEP_SECONDS)
                continue

            _process([message for _, message in batch])
            # Acknowledge only after the batch is durably written.
            queue.ack_batch(RAW_EVENTS_TOPIC, [entry_id for entry_id, _ in batch])
        except Exception:  # noqa: BLE001 - the worker must outlive a transient failure
            log.exception("worker loop iteration failed; retrying")
            time.sleep(IDLE_SLEEP_SECONDS * 5)

    log.info("ingestion worker stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(run())
