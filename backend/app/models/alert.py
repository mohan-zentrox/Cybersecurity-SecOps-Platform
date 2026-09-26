"""
Alert model.

FRD ref: FRD-ALERT-01/02 — created by the rule engine when a
DetectionRule matches normalized events. `dedup_key` prevents the same
underlying condition (rule + grouping key, e.g. rule 12 + source.ip
10.0.0.5) from spawning duplicate alerts on repeated rule evaluation runs.
`status` is governed by the shared state machine in
services/state_machine.py (new -> investigating -> closed|escalated).

The lifecycle timestamps exist so SOC KPIs are computable without
reconstructing history from the audit log:
  * `first_event_at`     — earliest matched event time; MTTD = created_at - first_event_at
  * `acknowledged_at`    — first move off `new`
  * `closed_at`          — reached the terminal `closed` state; MTTR = closed_at - created_at
  * `sla_due_at` / `sla_breached` — severity-driven response deadline (FRD-ALERT-05)
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON


class AlertStatus:
    NEW = "new"
    INVESTIGATING = "investigating"
    CLOSED = "closed"
    ESCALATED = "escalated"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("detection_rules.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=AlertStatus.NEW)
    dedup_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    matched_event_ids: Mapped[list] = mapped_column(PortableJSON, default=list)

    # Threat-intel annotations attached by services/enrichment.py at alert time.
    enrichment: Mapped[dict] = mapped_column(PortableJSON, default=dict)

    # --- Lifecycle timestamps / SLA (FRD-ALERT-05, FRD-KPI-01) ---
    first_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
