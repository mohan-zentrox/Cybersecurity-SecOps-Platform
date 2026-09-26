from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventIngestRequest(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=10_000)


class IngestSummaryOut(BaseModel):
    accepted: int
    dead_lettered: int
    threat_matches: int = 0
    stored_event_ids: list[int]
    alerts_created: list[int] = []
    queued_only: bool = False


class NormalizedEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_action: str | None
    event_category: str | None
    event_outcome: str | None
    source_ip: str | None
    destination_ip: str | None
    user_name: str | None
    host_name: str | None
    event_timestamp: datetime
    ingested_at: datetime
    threat_matched: bool
    ecs: dict[str, Any]


class NormalizedEventDetailOut(NormalizedEventOut):
    raw: dict[str, Any]
    enrichment: dict[str, Any]


class DeadLetterOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    raw_payload: dict[str, Any]
    error_message: str
    received_at: datetime
    replayed_at: datetime | None
    replay_status: str | None
    resolved: bool


class DeadLetterReplayRequest(BaseModel):
    """Replay specific dead letters, or omit ids to replay every unresolved one."""

    dead_letter_ids: list[int] | None = None


class DeadLetterReplayResult(BaseModel):
    attempted: int
    succeeded: int
    still_failing: int
    alerts_created: list[int] = []
