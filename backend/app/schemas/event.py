from typing import Any

from pydantic import BaseModel, Field


class EventIngestRequest(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1)


class IngestSummaryOut(BaseModel):
    accepted: int
    dead_lettered: int
    stored_event_ids: list[int]
    alerts_created: list[int] = []
