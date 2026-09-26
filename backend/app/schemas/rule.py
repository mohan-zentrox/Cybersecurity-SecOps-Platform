from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class RuleCondition(BaseModel):
    field: str = Field(min_length=1, max_length=256)
    operator: Literal["eq", "neq", "contains", "gt", "gte", "lt", "lte", "in", "regex", "exists"]
    value: Any = None


class RuleThreshold(BaseModel):
    count: int = Field(gt=0)
    window_seconds: int = Field(gt=0)
    group_by: str | None = None


class RuleLogic(BaseModel):
    match: Literal["all", "any"] = "all"
    conditions: list[RuleCondition] = Field(min_length=1)
    threshold: RuleThreshold | None = None


class RuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    severity: Literal["low", "medium", "high", "critical"]
    mitre_technique_id: str | None = None
    logic: RuleLogic
    enabled: bool = True


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    severity: str
    mitre_technique_id: str | None
    logic: dict
    enabled: bool
    eval_watermark: datetime | None
    last_evaluated_at: datetime | None
    alert_count: int
    created_by: int | None
    created_at: datetime
    updated_at: datetime


class RuleUpdate(BaseModel):
    """Partial update. Every field is optional; omitted fields are left alone."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    mitre_technique_id: str | None = Field(default=None, max_length=16)
    logic: RuleLogic | None = None
    enabled: bool | None = None


class RuleToggle(BaseModel):
    enabled: bool


class RuleTestRequest(BaseModel):
    sample_events: list[dict[str, Any]] = Field(min_length=1)


class RuleTestMatchOut(BaseModel):
    group_key: str | None
    event_ids: list[Any]
    sample_event_id: Any


class RuleTestResponse(BaseModel):
    rule_id: int
    matched_count: int
    matches: list[RuleTestMatchOut]


class RuleEvaluateResponse(BaseModel):
    rule_id: int
    matches_found: int
    alerts_created: int
    alert_ids: list[int]
    events_scanned: int = 0
