"""
ECS normalization pipeline.

FRD ref: FRD-ING-01/02 — raw events from heterogeneous sources (arbitrary
field names) are mapped onto an ECS (Elastic Common Schema)-aligned shape
so downstream detection rules can be written against stable field paths
like `event.action`, `source.ip`, `user.name` regardless of the original
producer's vocabulary. Events that cannot be normalized (missing required
fields, unparsable timestamps) are written to the dead-letter table
instead of being dropped.

Event store abstraction (repository pattern)
----------------------------------------------
`EventStoreRepository` is the interface the rule engine and API layer
depend on. `PostgresJSONBEventStore` is the concrete implementation used
today, backed by the `normalized_events` table (JSON/JSONB column, see
app/models/event.py). A future OpenSearch/Elastic-backed implementation
(`OpenSearchEventStore`, not implemented here — see FRD-ING-04) would
implement the exact same `write_event` / `query_events` methods, letting
the platform scale event search without touching callers. Tests exercise
the interface against SQLite, proving the abstraction is engine-agnostic.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.event import DeadLetterEvent, NormalizedEvent

# Field aliases accepted from arbitrary raw producers, mapped to ECS paths.
_ALIASES: dict[str, tuple[str, ...]] = {
    "event.action": ("event.action", "event_action", "action"),
    "event.category": ("event.category", "event_category", "category"),
    "event.outcome": ("event.outcome", "event_outcome", "outcome"),
    "source.ip": ("source.ip", "source_ip", "src_ip", "srcip"),
    "destination.ip": ("destination.ip", "destination_ip", "dst_ip", "dstip"),
    "user.name": ("user.name", "user_name", "username", "user"),
    "host.name": ("host.name", "host_name", "hostname", "host"),
    "@timestamp": ("@timestamp", "timestamp", "event_timestamp", "time"),
}

REQUIRED_ECS_FIELDS = ("event.action", "@timestamp")


class NormalizationError(Exception):
    pass


def _get_alias(raw: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for alias in aliases:
        if "." in alias:
            # Allow raw payloads that are already partially ECS-nested, e.g. {"event": {"action": ...}}
            top, _, rest = alias.partition(".")
            if isinstance(raw.get(top), dict) and rest in raw[top]:
                return raw[top][rest]
        if alias in raw and raw[alias] is not None:
            return raw[alias]
    return None


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            iso_value = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError as exc:
            raise NormalizationError(f"Unparsable timestamp: {value!r}") from exc
    raise NormalizationError(f"Unsupported timestamp type: {type(value)!r}")


def _set_nested(d: dict, dotted_key: str, value: Any) -> None:
    parts = dotted_key.split(".")
    cur = d
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def normalize_raw_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a raw event dict onto an ECS-aligned dict. Raises NormalizationError on failure."""
    if not isinstance(raw, dict):
        raise NormalizationError("Raw event must be a JSON object")

    ecs: dict[str, Any] = {}
    for ecs_field, aliases in _ALIASES.items():
        value = _get_alias(raw, aliases)
        if ecs_field == "@timestamp":
            continue  # handled separately below (needs parsing, not raw passthrough)
        if value is not None:
            _set_nested(ecs, ecs_field, value)

    raw_ts = _get_alias(raw, _ALIASES["@timestamp"])
    for required in REQUIRED_ECS_FIELDS:
        if required == "@timestamp":
            if raw_ts is None:
                raise NormalizationError("Missing required field: timestamp")
            continue
        top, _, rest = required.partition(".")
        if top not in ecs or rest not in ecs[top]:
            raise NormalizationError(f"Missing required ECS field: {required}")

    ts = _parse_timestamp(raw_ts)
    ecs["@timestamp"] = ts.isoformat()

    return {"ecs": ecs, "timestamp": ts}


@dataclass
class EventQuery:
    event_action: str | None = None
    event_category: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user_name: str | None = None
    host_name: str | None = None
    threat_matched: bool | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = 10_000
    offset: int = 0


@dataclass
class StoredEvent:
    id: int
    ecs: dict[str, Any]
    timestamp: datetime
    raw: dict[str, Any] = field(default_factory=dict)


class EventStoreRepository(ABC):
    """Repository-pattern interface: swap Postgres/JSONB for OpenSearch without touching callers."""

    @abstractmethod
    def write_event(self, ecs: dict[str, Any], raw: dict[str, Any], timestamp: datetime) -> StoredEvent: ...

    @abstractmethod
    def query_events(self, query: EventQuery) -> list[StoredEvent]: ...

    @abstractmethod
    def count_events(self, query: EventQuery) -> int: ...


class PostgresJSONBEventStore(EventStoreRepository):
    """Event store backed by the `normalized_events` table (JSON/JSONB column).

    Despite the name, this transparently runs on SQLite in tests via the
    `PortableJSON` column type (see app/db/base.py) — no test-only branching.
    """

    def __init__(self, db: Session):
        self.db = db

    def write_event(self, ecs: dict[str, Any], raw: dict[str, Any], timestamp: datetime) -> StoredEvent:
        row = NormalizedEvent(
            event_action=ecs.get("event", {}).get("action"),
            event_category=ecs.get("event", {}).get("category"),
            event_outcome=ecs.get("event", {}).get("outcome"),
            source_ip=ecs.get("source", {}).get("ip"),
            destination_ip=ecs.get("destination", {}).get("ip"),
            user_name=ecs.get("user", {}).get("name"),
            host_name=ecs.get("host", {}).get("name"),
            event_timestamp=timestamp,
            ecs=ecs,
            raw=raw,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return StoredEvent(id=row.id, ecs=row.ecs, timestamp=row.event_timestamp, raw=row.raw)

    def _filtered(self, query: EventQuery):
        q = self.db.query(NormalizedEvent)
        if query.event_action:
            q = q.filter(NormalizedEvent.event_action == query.event_action)
        if query.event_category:
            q = q.filter(NormalizedEvent.event_category == query.event_category)
        if query.source_ip:
            q = q.filter(NormalizedEvent.source_ip == query.source_ip)
        if query.destination_ip:
            q = q.filter(NormalizedEvent.destination_ip == query.destination_ip)
        if query.user_name:
            q = q.filter(NormalizedEvent.user_name == query.user_name)
        if query.host_name:
            q = q.filter(NormalizedEvent.host_name == query.host_name)
        if query.threat_matched is not None:
            q = q.filter(NormalizedEvent.threat_matched.is_(query.threat_matched))
        if query.since:
            q = q.filter(NormalizedEvent.event_timestamp >= query.since)
        if query.until:
            q = q.filter(NormalizedEvent.event_timestamp <= query.until)
        return q

    def query_events(self, query: EventQuery) -> list[StoredEvent]:
        rows = (
            self._filtered(query)
            .order_by(NormalizedEvent.event_timestamp.asc())
            .limit(query.limit)
            .offset(query.offset)
            .all()
        )
        return [StoredEvent(id=r.id, ecs=r.ecs, timestamp=r.event_timestamp, raw=r.raw) for r in rows]

    def count_events(self, query: EventQuery) -> int:
        return self._filtered(query).count()


def write_dead_letter(db: Session, raw_payload: dict[str, Any], error_message: str) -> DeadLetterEvent:
    row = DeadLetterEvent(raw_payload=raw_payload, error_message=error_message)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@dataclass
class IngestSummary:
    accepted: int = 0
    dead_lettered: int = 0
    threat_matches: int = 0
    stored_event_ids: list[int] = field(default_factory=list)


def process_raw_batch(db: Session, raw_events: list[dict[str, Any]]) -> IngestSummary:
    """Normalize and persist a batch of raw events, dead-lettering failures.

    In this foundation repo the queue is drained synchronously within the
    ingest request (dev/test-friendly and deterministic). In a scaled
    deployment this function is what a separate consumer process/worker
    would call after popping messages off Redis Streams/Kafka — see
    services/queue.py and api/v1/events.py for where the hand-off happens.
    """
    from app.services.enrichment import enrich_events  # local import: avoids a cycle

    store = PostgresJSONBEventStore(db)
    summary = IngestSummary()
    for raw in raw_events:
        try:
            normalized = normalize_raw_event(raw)
        except NormalizationError as exc:
            write_dead_letter(db, raw, str(exc))
            summary.dead_lettered += 1
            continue
        stored = store.write_event(normalized["ecs"], raw, normalized["timestamp"])
        summary.accepted += 1
        summary.stored_event_ids.append(stored.id)

    # Threat-intel enrichment runs after persistence so matched indicators are
    # written onto the stored ECS document and are therefore visible to the
    # detection rules that run next (FRD-TI-03).
    if summary.stored_event_ids:
        rows = db.query(NormalizedEvent).filter(NormalizedEvent.id.in_(summary.stored_event_ids)).all()
        enrichment = enrich_events(db, rows)
        summary.threat_matches = enrichment.events_matched

    return summary
