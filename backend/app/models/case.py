"""
Case management models.

FRD ref: FRD-CASE-01..05 — one or more Alerts are promoted into a Case for
investigation. `CaseTimelineEvent` rows are append-only (no UPDATE/DELETE
route exists for them) and record every status change, comment, and
assignment so a case has an immutable audit trail independent of the
global hash-chained AuditEvent log. `sla_due_at` is computed at creation
time from the severity-to-minutes mapping in core/config.py.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON


class CaseStatus:
    NEW = "new"
    INVESTIGATING = "investigating"
    CLOSED = "closed"
    ESCALATED = "escalated"


class TimelineEventType:
    STATUS_CHANGE = "status_change"
    COMMENT = "comment"
    ASSIGNMENT = "assignment"
    ALERT_LINKED = "alert_linked"
    CREATED = "created"


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=CaseStatus.NEW)
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    sla_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class CaseAlertLink(Base):
    """Many-to-many association between promoted Alerts and a Case."""

    __tablename__ = "case_alert_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False, index=True)


class CaseTimelineEvent(Base):
    """Append-only timeline entry. No update/delete API is exposed for this table."""

    __tablename__ = "case_timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[dict] = mapped_column(PortableJSON, default=dict)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
