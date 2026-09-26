from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ChannelTypeLiteral = Literal["webhook", "slack", "email", "log"]
SeverityLiteral = Literal["low", "medium", "high", "critical"]


class ChannelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    enabled: bool
    min_severity: str
    config: dict[str, Any]
    created_at: datetime


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    type: ChannelTypeLiteral
    enabled: bool = True
    min_severity: SeverityLiteral = "medium"
    config: dict[str, Any] = {}


class ChannelUpdate(BaseModel):
    enabled: bool | None = None
    min_severity: SeverityLiteral | None = None
    config: dict[str, Any] | None = None


class DeliveryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    channel_id: int | None
    channel_name: str
    channel_type: str
    subject_type: str
    subject_id: int | None
    status: str
    detail: str
    attempted_at: datetime


class ChannelTestResult(BaseModel):
    channel_name: str
    status: str
    detail: str
