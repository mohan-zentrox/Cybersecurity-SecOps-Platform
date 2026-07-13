"""
FRD ref: FRD-ING-01/02/03 — batch ingestion -> queue -> ECS normalization
-> event store, with dead-lettering of unparsable events. After a batch is
normalized, all enabled detection rules are re-evaluated against the event
store so new alerts surface immediately (see services/rule_engine.py).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db
from app.models.rule import DetectionRule
from app.models.user import User
from app.schemas.event import EventIngestRequest, IngestSummaryOut
from app.services.audit_chain import append_audit_event
from app.services.normalizer import process_raw_batch
from app.services.queue import get_queue
from app.services.rule_engine import run_rule_against_store

router = APIRouter(prefix="/events", tags=["events"])

RAW_EVENTS_TOPIC = "raw_events"


@router.post("/ingest", response_model=IngestSummaryOut)
def ingest_events(
    payload: EventIngestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IngestSummaryOut:
    queue = get_queue()
    for raw_event in payload.events:
        queue.enqueue(RAW_EVENTS_TOPIC, raw_event)

    # In this foundation repo the consumer runs inline within the request so
    # ingestion is synchronous and deterministic for tests/dev. In a scaled
    # deployment, a separate worker process would call process_raw_batch()
    # after popping messages off Redis Streams/Kafka (see services/queue.py).
    batch = queue.dequeue_batch(RAW_EVENTS_TOPIC, max_messages=len(payload.events))
    summary = process_raw_batch(db, batch)

    append_audit_event(
        db,
        actor=current_user.username,
        action="events_ingested",
        resource="events:ingest",
        details={"accepted": summary.accepted, "dead_lettered": summary.dead_lettered},
    )

    alerts_created: list[int] = []
    if summary.accepted:
        enabled_rules = db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all()
        for rule in enabled_rules:
            result = run_rule_against_store(db, rule)
            alerts_created.extend(a.id for a in result.created_alerts)

    return IngestSummaryOut(
        accepted=summary.accepted,
        dead_lettered=summary.dead_lettered,
        stored_event_ids=summary.stored_event_ids,
        alerts_created=alerts_created,
    )
