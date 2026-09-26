from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ResolutionLiteral = Literal[
    "true_positive", "false_positive", "benign_true_positive", "duplicate", "inconclusive"
]


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    severity: str
    status: str
    assigned_to: int | None
    sla_due_at: datetime
    sla_breached: bool
    closed_at: datetime | None
    resolution: str | None
    resolution_summary: str | None
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
    vulnerability_ids: list[int] = []


class CaseStatusUpdate(BaseModel):
    status: Literal["new", "investigating", "closed", "escalated"]
    resolution: ResolutionLiteral | None = None
    resolution_summary: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def _closure_requires_disposition(self) -> "CaseStatusUpdate":
        # FRD-CASE-06: a case may not be closed without recording why. Without
        # this, "closed" carries no analytical meaning and false-positive rate
        # (the number that drives rule tuning) cannot be computed.
        if self.status == "closed" and self.resolution is None:
            raise ValueError("Closing a case requires a 'resolution'")
        return self


class CaseCommentCreate(BaseModel):
    comment: str = Field(min_length=1, max_length=4000)


class CaseAssign(BaseModel):
    assigned_to: int | None = None
