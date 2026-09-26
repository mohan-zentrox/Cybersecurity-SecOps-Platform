"""
Event store models.

FRD ref: FRD-ING-01/02 — raw events are ingested, queued, and normalized
into an ECS (Elastic Common Schema)-aligned shape. `NormalizedEvent` is a
PostgreSQL-JSONB-backed implementation of the repository-pattern event
store interface defined in services/normalizer.py's `EventStoreRepository`
ABC. An OpenSearch/Elastic-backed implementation of the same interface can
be dropped in for production-scale search without touching callers — see
the docstring on that ABC for the extension contract.

`DeadLetterEvent` captures raw payloads that failed ECS normalization
(malformed JSON, missing required fields, type coercion errors) so they
can be inspected and replayed rather than silently dropped.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON


class NormalizedEvent(Base):
    """ECS-aligned normalized security event."""

    __tablename__ = "normalized_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # --- Core ECS fields used by the detection rule engine ---
    event_action: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    event_category: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    event_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_name: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    host_name: Mapped[str | None] = mapped_column(String(128), nullable=True)

    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Full ECS document (superset of the promoted columns above) plus the
    # original raw payload, preserved for forensic replay.
    ecs: Mapped[dict] = mapped_column(PortableJSON, default=dict)
    raw: Mapped[dict] = mapped_column(PortableJSON, default=dict)

    # threat.indicator.* annotations written by services/enrichment.py.
    enrichment: Mapped[dict] = mapped_column(PortableJSON, default=dict)
    threat_matched: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)


class DeadLetterEvent(Base):
    """Raw events that failed normalization."""

    __tablename__ = "dead_letter_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    raw_payload: Mapped[dict] = mapped_column(PortableJSON, default=dict)
    error_message: Mapped[str] = mapped_column(String(1024), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Replay bookkeeping (FRD-ING-05): a dead letter can be re-submitted
    # through the normalizer once the upstream producer is fixed.
    replayed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replay_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
