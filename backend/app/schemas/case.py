from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    severity: str
    status: str
    assigned_to: int | None
    sla_due_at: datetime
    created_at: datetime
    updated_at: datetime


class CaseTimelineEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    type: str
    content: dict[str, Any]
    actor: str
    created_at: datetime


class CaseDetailOut(CaseOut):
    timeline: list[CaseTimelineEventOut]
    alert_ids: list[int]


class CaseStatusUpdate(BaseModel):
    status: Literal["new", "investigating", "closed", "escalated"]


class CaseCommentCreate(BaseModel):
    comment: str


class CaseAssign(BaseModel):
    assigned_to: int
