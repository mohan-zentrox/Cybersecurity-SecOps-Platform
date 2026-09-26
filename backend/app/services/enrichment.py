"""
Threat-intelligence enrichment.

FRD ref: FRD-TI-03 — after an event is normalized, its network and file
identifiers are looked up against the stored IOC set. Matches are written
back onto the event as ECS ``threat.indicator.*`` fields so detection rules
can be written against them exactly like any other field, e.g.::

    {"field": "threat.indicator.matched", "operator": "eq", "value": true}
    {"field": "threat.indicator.max_confidence", "operator": "gte", "value": 75}

Lookups are batched: one query per IOC type per batch rather than one
query per event, so enriching a 10k-event batch stays a handful of
round-trips instead of tens of thousands.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.event import NormalizedEvent
from app.models.ioc import IOC, IOCType, normalize_ioc_value

log = logging.getLogger("aegis.enrichment")

# Which ECS paths inside an event carry a candidate value for each IOC type.
_ECS_PATHS_BY_TYPE: dict[str, tuple[str, ...]] = {
    IOCType.IP: ("source.ip", "destination.ip", "client.ip", "server.ip"),
    IOCType.DOMAIN: ("dns.question.name", "url.domain", "destination.domain"),
    IOCType.URL: ("url.full", "url.original"),
    IOCType.FILE_HASH: ("file.hash.sha256", "file.hash.md5", "file.hash.sha1", "process.hash.sha256"),
    IOCType.EMAIL: ("user.email", "email.from.address"),
}


def _get_by_path(document: dict, path: str) -> Any:
    cursor: Any = document
    for part in path.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


def extract_candidates(ecs: dict[str, Any]) -> dict[str, set[str]]:
    """Pull every enrichable value out of one ECS document, keyed by IOC type."""
    candidates: dict[str, set[str]] = {}
    for ioc_type, paths in _ECS_PATHS_BY_TYPE.items():
        for path in paths:
            value = _get_by_path(ecs, path)
            if isinstance(value, str) and value.strip():
                candidates.setdefault(ioc_type, set()).add(normalize_ioc_value(value))
    return candidates


@dataclass
class EnrichmentResult:
    events_enriched: int = 0
    events_matched: int = 0
    indicators_hit: set[int] = field(default_factory=set)


def _active_iocs(db: Session, wanted: dict[str, set[str]]) -> dict[tuple[str, str], IOC]:
    """Batch-load the active IOCs matching any candidate value. One query per type."""
    now = datetime.now(timezone.utc)
    found: dict[tuple[str, str], IOC] = {}
    for ioc_type, values in wanted.items():
        if not values:
            continue
        rows = (
            db.query(IOC)
            .filter(IOC.type == ioc_type, IOC.active.is_(True), IOC.value_normalized.in_(list(values)))
            .all()
        )
        for row in rows:
            if row.expires_at is not None:
                expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
                if expires < now:
                    continue
            found[(row.type, row.value_normalized)] = row
    return found


def build_enrichment(matched: list[IOC]) -> dict[str, Any]:
    """Render matched indicators into an ECS-shaped ``threat.indicator`` block."""
    if not matched:
        return {}
    return {
        "matched": True,
        "count": len(matched),
        "max_confidence": max(i.confidence for i in matched),
        "max_severity": max(
            (i.severity for i in matched),
            key=lambda s: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(s, 0),
        ),
        "indicators": [
            {
                "id": i.id,
                "type": i.type,
                "value": i.value,
                "confidence": i.confidence,
                "severity": i.severity,
                "source": i.source,
                "tags": i.tags or [],
            }
            for i in matched
        ],
    }


def enrich_events(db: Session, events: list[NormalizedEvent]) -> EnrichmentResult:
    """Annotate a batch of persisted events in place with threat-intel matches."""
    result = EnrichmentResult()
    if not events:
        return result

    # Pass 1: collect every candidate value across the whole batch.
    per_event: list[dict[str, set[str]]] = []
    batch_wanted: dict[str, set[str]] = {}
    for event in events:
        candidates = extract_candidates(event.ecs or {})
        per_event.append(candidates)
        for ioc_type, values in candidates.items():
            batch_wanted.setdefault(ioc_type, set()).update(values)

    if not batch_wanted:
        return result

    # Pass 2: one batched lookup, then annotate each event from the cache.
    lookup = _active_iocs(db, batch_wanted)
    if not lookup:
        return result

    now = datetime.now(timezone.utc)
    for event, candidates in zip(events, per_event):
        matched = [
            lookup[(ioc_type, value)]
            for ioc_type, values in candidates.items()
            for value in values
            if (ioc_type, value) in lookup
        ]
        if not matched:
            continue

        indicator_block = build_enrichment(matched)
        event.enrichment = {"threat": {"indicator": indicator_block}}
        event.threat_matched = True

        # Mirror into the ECS document so rule conditions can target
        # `threat.indicator.*` with the same path syntax as any other field.
        ecs = dict(event.ecs or {})
        ecs["threat"] = {"indicator": indicator_block}
        event.ecs = ecs

        for ioc in matched:
            ioc.match_count += 1
            ioc.last_seen = now
            result.indicators_hit.add(ioc.id)
        result.events_matched += 1

    result.events_enriched = len(events)
    db.commit()

    if result.events_matched:
        log.info(
            "threat intel enrichment matched events",
            extra={
                "aegis.events_matched": result.events_matched,
                "aegis.indicators_hit": len(result.indicators_hit),
            },
        )
    return result


def upsert_ioc(
    db: Session,
    *,
    ioc_type: str,
    value: str,
    confidence: int = 50,
    severity: str = "medium",
    description: str = "",
    tags: list[str] | None = None,
    source: str = "manual",
    feed_id: int | None = None,
    expires_at: datetime | None = None,
) -> tuple[IOC, bool]:
    """Insert or refresh one indicator. Returns (row, created)."""
    normalized = normalize_ioc_value(value)
    existing = db.query(IOC).filter(IOC.type == ioc_type, IOC.value_normalized == normalized).first()
    now = datetime.now(timezone.utc)

    if existing is not None:
        existing.confidence = max(existing.confidence, confidence)
        existing.severity = severity or existing.severity
        existing.last_seen = now
        existing.active = True
        if description:
            existing.description = description
        if tags:
            existing.tags = sorted(set((existing.tags or []) + tags))
        if expires_at is not None:
            existing.expires_at = expires_at
        db.commit()
        db.refresh(existing)
        return existing, False

    row = IOC(
        type=ioc_type,
        value=value.strip(),
        value_normalized=normalized,
        confidence=confidence,
        severity=severity,
        description=description,
        tags=tags or [],
        source=source,
        feed_id=feed_id,
        first_seen=now,
        last_seen=now,
        expires_at=expires_at,
        active=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, True
