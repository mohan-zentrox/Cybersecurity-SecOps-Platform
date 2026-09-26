"""
Detection rule model.

FRD ref: FRD-DET-01/02 — analysts/detection-engineers author rules made of
simple field/operator/value conditions plus an optional threshold-over-
window clause (e.g. "5+ failed logons from the same source.ip in 5
minutes"). The rule `logic` JSON shape is validated by
app/schemas/rule.py::RuleLogic and executed by services/rule_engine.py.

Example `logic` payload::

    {
        "match": "all",              # "all" (AND) | "any" (OR)
        "conditions": [
            {"field": "event.action", "operator": "eq", "value": "logon_failed"}
        ],
        "threshold": {
            "count": 5,
            "window_seconds": 300,
            "group_by": "source.ip"
        }
    }
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON


class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    ALL = (LOW, MEDIUM, HIGH, CRITICAL)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default=Severity.MEDIUM)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    logic: Mapped[dict] = mapped_column(PortableJSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Incremental-evaluation watermark: the newest event timestamp this rule
    # has already been evaluated against. services/rule_engine.py only reads
    # events newer than (watermark - RULE_EVAL_LOOKBACK_SECONDS) so a full
    # table scan is not required on every ingest batch.
    eval_watermark: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
