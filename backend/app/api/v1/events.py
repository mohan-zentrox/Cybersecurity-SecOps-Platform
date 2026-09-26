"""
FRD ref: FRD-ING-01..05 — batch ingestion -> queue -> ECS normalization ->
threat-intel enrichment -> event store, with dead-lettering of unparsable
events, a searchable event index, and a dead-letter replay path.

Ingestion mode is configurable (`INGEST_MODE`):
  * ``inline`` — this request drains the queue itself. Deterministic, which
    is what tests and a single-process dev server want.
  * ``worker`` — this request only enqueues and returns; app/worker.py does
    the work. That is what makes the queue actually absorb load.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.event import DeadLetterEvent, NormalizedEvent
from app.models.user import AppRole, User
from app.schemas.event import (
    DeadLetterOut,
    DeadLetterReplayRequest,
    DeadLetterReplayResult,
    EventIngestRequest,
    IngestSummaryOut,
    NormalizedEventDetailOut,
    NormalizedEventOut,
)
from app.services.audit_chain import append_audit_event
from app.services.normalizer import NormalizationError, normalize_raw_event, process_raw_batch
from app.services.queue import get_queue
from app.services.rule_engine import run_all_enabled_rules

router = APIRouter(prefix="/events", tags=["events"])

RAW_EVENTS_TOPIC = "raw_events"

_DLQ_MANAGERS = (AppRole.DETECTION_ENGINEER, AppRole.ADMIN)


@router.post("/ingest", response_model=IngestSummaryOut)
def ingest_events(
    payload: EventIngestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IngestSummaryOut:
    settings = get_settings()
    queue = get_queue()
    for raw_event in payload.events:
        queue.enqueue(RAW_EVENTS_TOPIC, raw_event)

    if settings.INGEST_MODE == "worker":
        # Hand off and return; app/worker.py normalizes and detects. The queue
        # absorbs the spike instead of the request holding it open.
        append_audit_event(
            db,
            actor=current_user.username,
            action="events_queued",
            resource="events:ingest",
            details={"queued": len(payload.events)},
        )
        return IngestSummaryOut(
            accepted=0, dead_lettered=0, stored_event_ids=[], alerts_created=[], queued_only=True
        )

    batch = queue.dequeue_batch(RAW_EVENTS_TOPIC, max_messages=len(payload.events))
    summary = process_raw_batch(db, batch)

    append_audit_event(
        db,
        actor=current_user.username,
        action="events_ingested",
        resource="events:ingest",
        details={
            "accepted": summary.accepted,
            "dead_lettered": summary.dead_lettered,
            "threat_matches": summary.threat_matches,
        },
    )

    alerts_created = [a.id for a in run_all_enabled_rules(db)] if summary.accepted else []

    return IngestSummaryOut(
        accepted=summary.accepted,
        dead_lettered=summary.dead_lettered,
        threat_matches=summary.threat_matches,
        stored_event_ids=summary.stored_event_ids,
        alerts_created=alerts_created,
    )


@router.get("", response_model=Page[NormalizedEventOut])
def search_events(
    event_action: str | None = None,
    event_category: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    user_name: str | None = None,
    host_name: str | None = None,
    threat_matched: bool | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[NormalizedEventOut]:
    """Search the normalized event store. Backed by the promoted ECS columns,
    which are indexed — the JSON document is returned, not filtered on."""
    query = db.query(NormalizedEvent)
    if event_action:
        query = query.filter(NormalizedEvent.event_action == event_action)
    if event_category:
        query = query.filter(NormalizedEvent.event_category == event_category)
    if source_ip:
        query = query.filter(NormalizedEvent.source_ip == source_ip)
    if destination_ip:
        query = query.filter(NormalizedEvent.destination_ip == destination_ip)
    if user_name:
        query = query.filter(NormalizedEvent.user_name == user_name)
    if host_name:
        query = query.filter(NormalizedEvent.host_name == host_name)
    if threat_matched is not None:
        query = query.filter(NormalizedEvent.threat_matched.is_(threat_matched))
    if since:
        query = query.filter(NormalizedEvent.event_timestamp >= since)
    if until:
        query = query.filter(NormalizedEvent.event_timestamp <= until)

    rows, total = paginate(db, query.order_by(NormalizedEvent.event_timestamp.desc()), params)
    return Page[NormalizedEventOut](
        items=[NormalizedEventOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/dead-letters", response_model=Page[DeadLetterOut])
def list_dead_letters(
    resolved: bool | None = Query(default=None),
    params: PageParams = Depends(page_params),
    current_user: User = Depends(require_roles(*_DLQ_MANAGERS)),
    db: Session = Depends(get_db),
) -> Page[DeadLetterOut]:
    """Events that failed normalization. Previously write-only — a dead-letter
    queue nobody can read is just a slower way of dropping data."""
    query = db.query(DeadLetterEvent)
    if resolved is not None:
        query = query.filter(DeadLetterEvent.resolved.is_(resolved))
    rows, total = paginate(db, query.order_by(DeadLetterEvent.received_at.desc()), params)
    return Page[DeadLetterOut](
        items=[DeadLetterOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.post("/dead-letters/replay", response_model=DeadLetterReplayResult)
def replay_dead_letters(
    payload: DeadLetterReplayRequest,
    current_user: User = Depends(require_roles(*_DLQ_MANAGERS)),
    db: Session = Depends(get_db),
) -> DeadLetterReplayResult:
    """Re-run stored raw payloads through the normalizer once the upstream
    producer has been fixed. A payload that still fails is re-dead-lettered
    by `process_raw_batch`, so nothing is lost on a failed replay."""
    query = db.query(DeadLetterEvent).filter(DeadLetterEvent.resolved.is_(False))
    if payload.dead_letter_ids:
        query = query.filter(DeadLetterEvent.id.in_(payload.dead_letter_ids))
    rows = query.all()

    if not rows:
        return DeadLetterReplayResult(attempted=0, succeeded=0, still_failing=0)

    # Re-validate each payload individually first, so a row that still fails is
    # marked with its reason rather than being dead-lettered a second time by
    # the batch path (which would grow the DLQ on every replay attempt).
    now = datetime.now(timezone.utc)
    replayable: list[dict] = []
    for row in rows:
        try:
            normalize_raw_event(row.raw_payload)
        except NormalizationError as exc:
            row.replayed_at = now
            row.replay_status = f"failed: {exc}"[:32]
            continue
        replayable.append(row.raw_payload)
        row.resolved = True
        row.replayed_at = now
        row.replay_status = "succeeded"

    summary = process_raw_batch(db, replayable) if replayable else None
    db.commit()

    succeeded = len(replayable)
    append_audit_event(
        db,
        actor=current_user.username,
        action="dead_letters_replayed",
        resource="events:dead-letters",
        details={"attempted": len(rows), "succeeded": succeeded},
    )

    alerts_created = [a.id for a in run_all_enabled_rules(db)] if summary and summary.accepted else []
    return DeadLetterReplayResult(
        attempted=len(rows),
        succeeded=succeeded,
        still_failing=len(rows) - succeeded,
        alerts_created=alerts_created,
    )


@router.get("/{event_id}", response_model=NormalizedEventDetailOut)
def get_event(
    event_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> NormalizedEvent:
    event = db.query(NormalizedEvent).filter(NormalizedEvent.id == event_id).first()
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
