from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


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
    created_at: datetime
    updated_at: datetime


class AlertStatusUpdate(BaseModel):
    status: Literal["new", "investigating", "closed", "escalated"]


class AlertAssign(BaseModel):
    assigned_to: int


class PromoteToCaseRequest(BaseModel):
    alert_ids: list[int]
    title: str | None = None
