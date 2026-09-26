from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: int | None
    title: str
    severity: str
    status: str
    dedup_key: str
    assigned_to: int | None
    matched_event_ids: list[Any]
    enrichment: dict[str, Any]
    first_event_at: datetime | None
    acknowledged_at: datetime | None
    closed_at: datetime | None
    sla_due_at: datetime | None
    sla_breached: bool
    created_at: datetime
    updated_at: datetime


class AlertStatusUpdate(BaseModel):
    status: Literal["new", "investigating", "closed", "escalated"]


class AlertAssign(BaseModel):
    # None clears the assignment (returns the alert to the unassigned pool).
    assigned_to: int | None = None


class AlertBulkStatusUpdate(BaseModel):
    """Bulk triage — the single most common analyst action on a noisy queue."""

    alert_ids: list[int] = Field(min_length=1, max_length=500)
    status: Literal["new", "investigating", "closed", "escalated"]


class AlertBulkResult(BaseModel):
    updated: list[int]
    failed: dict[str, str]


class PromoteToCaseRequest(BaseModel):
    alert_ids: list[int] = Field(min_length=1)
    title: str | None = None
