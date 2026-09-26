from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

IOCTypeLiteral = Literal["ip", "domain", "url", "file_hash", "email"]
SeverityLiteral = Literal["low", "medium", "high", "critical"]


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    type: str
    value: str
    confidence: int
    severity: str
    description: str
    tags: list[str]
    source: str
    feed_id: int | None
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    active: bool
    match_count: int


class IOCCreate(BaseModel):
    type: IOCTypeLiteral
    value: str = Field(min_length=1, max_length=1024)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: SeverityLiteral = "medium"
    description: str = Field(default="", max_length=2000)
    tags: list[str] = []
    expires_at: datetime | None = None


class IOCBulkCreate(BaseModel):
    indicators: list[IOCCreate] = Field(min_length=1, max_length=10_000)
    source: str = Field(default="manual", max_length=128)


class IOCBulkResult(BaseModel):
    created: int
    updated: int
    total: int


class IOCUpdate(BaseModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: SeverityLiteral | None = None
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = None
    active: bool | None = None
    expires_at: datetime | None = None


class FeedOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    kind: str
    url: str | None
    enabled: bool
    default_confidence: int
    last_polled_at: datetime | None
    last_poll_status: str | None
    last_poll_indicator_count: int
    created_at: datetime


class FeedCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: Literal["manual", "http_json", "otx", "misp"] = "manual"
    url: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    default_confidence: int = Field(default=50, ge=0, le=100)


class FeedPollResult(BaseModel):
    feed_name: str
    fetched: int
    created: int
    updated: int
    error: str | None = None
