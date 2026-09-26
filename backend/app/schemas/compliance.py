from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

FrameworkLiteral = Literal["SOC2", "ISO27001", "PCI-DSS"]


class ControlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    framework: str
    control_id: str
    title: str
    description: str
    evidence_collector: str
    enabled: bool


class ReportCreate(BaseModel):
    framework: FrameworkLiteral
    period_start: datetime
    period_end: datetime


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    framework: str
    period_start: datetime
    period_end: datetime
    status: str
    controls_total: int
    controls_passed: int
    controls_failed: int
    error_message: str | None
    generated_by: str
    created_at: datetime
    completed_at: datetime | None


class ReportDetailOut(ReportOut):
    results: dict[str, Any]
