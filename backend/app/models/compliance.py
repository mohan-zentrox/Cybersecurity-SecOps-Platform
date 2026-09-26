"""
Compliance reporting models.

FRD ref: FRD-COMP-01 — a `ComplianceControl` maps a framework control
(SOC2 CC7.2, ISO27001 A.12.4, PCI-DSS 10.2, ...) onto an *evidence
collector key*. The collector is a function in services/compliance.py that
queries data this platform already produces — the hash-chained audit log,
case SLA performance, detection-rule coverage — and returns a
pass/fail/not-applicable verdict plus supporting figures.

`ComplianceReport` is the generated artifact: a point-in-time snapshot of
every control verdict for one framework over one reporting period. The
rendered HTML is stored on the row so a report is immutable once generated
(regenerating produces a new row, it never mutates an old one).
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON


class Framework:
    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    PCI_DSS = "PCI-DSS"

    ALL = (SOC2, ISO27001, PCI_DSS)


class ControlVerdict:
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class ReportStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ComplianceControl(Base):
    """One framework control, bound to an automated evidence collector."""

    __tablename__ = "compliance_controls"
    __table_args__ = (UniqueConstraint("framework", "control_id", name="uq_control_framework_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), default="")
    # Key into services/compliance.py::EVIDENCE_COLLECTORS
    evidence_collector: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    status: Mapped[str] = mapped_column(String(16), default=ReportStatus.PENDING, nullable=False)
    controls_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    controls_passed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    controls_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Full per-control verdict payload, and the rendered HTML artifact.
    results: Mapped[dict] = mapped_column(PortableJSON, default=dict)
    rendered_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    generated_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
