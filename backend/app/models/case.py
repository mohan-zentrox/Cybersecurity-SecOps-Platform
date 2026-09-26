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

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON


class CaseStatus:
    NEW = "new"
    INVESTIGATING = "investigating"
    CLOSED = "closed"
    ESCALATED = "escalated"


class CaseResolution:
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    DUPLICATE = "duplicate"
    INCONCLUSIVE = "inconclusive"

    ALL = (TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_TRUE_POSITIVE, DUPLICATE, INCONCLUSIVE)


class TimelineEventType:
    STATUS_CHANGE = "status_change"
    COMMENT = "comment"
    ASSIGNMENT = "assignment"
    ALERT_LINKED = "alert_linked"
    CREATED = "created"
    SLA_BREACH = "sla_breach"
    VULNERABILITY_LINKED = "vulnerability_linked"


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=CaseStatus.NEW)
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    sla_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Populated when a case is closed; required by the API so every closure
    # records a disposition rather than silently vanishing (FRD-CASE-06).
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolution_summary: Mapped[str | None] = mapped_column(String(4000), nullable=True)

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
