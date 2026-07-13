from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    actor: str
    action: str
    resource: str
    details: dict[str, Any]
    prev_hash: str
    content_hash: str


class AuditVerifyResponse(BaseModel):
    intact: bool
    total_events: int
    first_broken_event_id: int | None
    reason: str | None
