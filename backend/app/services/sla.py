"""
SLA breach detection.

FRD ref: FRD-ALERT-05 / FRD-CASE-05 — computing `sla_due_at` at creation
time is only half the control; something has to notice when the deadline
passes. `sweep_sla_breaches` is run on an interval by
services/scheduler.py (and is directly callable from the API so an
operator can force a sweep).

A breach is recorded exactly once: the `sla_breached` flag is the guard,
so repeated sweeps do not re-notify. Breaching a case also writes an
immutable `SLA_BREACH` timeline entry, and every breach is appended to the
hash-chained audit log with `actor="system"`.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus
from app.models.case import Case, CaseStatus, CaseTimelineEvent, TimelineEventType
from app.services.audit_chain import append_audit_event
from app.services.notifications import dispatch, notification_for_sla_breach

log = logging.getLogger("aegis.sla")

SYSTEM_ACTOR = "system"


@dataclass
class SLASweepResult:
    alerts_breached: list[int]
    cases_breached: list[int]

    @property
    def total(self) -> int:
        return len(self.alerts_breached) + len(self.cases_breached)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def sweep_sla_breaches(db: Session, *, now: datetime | None = None, notify: bool = True) -> SLASweepResult:
    """Flag every open alert/case whose SLA deadline has elapsed."""
    now = now or datetime.now(timezone.utc)
    result = SLASweepResult(alerts_breached=[], cases_breached=[])

    open_alerts = (
        db.query(Alert)
        .filter(
            Alert.sla_breached.is_(False),
            Alert.sla_due_at.isnot(None),
            Alert.status != AlertStatus.CLOSED,
        )
        .all()
    )
    for alert in open_alerts:
        due = _as_utc(alert.sla_due_at)
        if due is None or due > now:
            continue
        alert.sla_breached = True
        db.commit()
        result.alerts_breached.append(alert.id)
        append_audit_event(
            db,
            actor=SYSTEM_ACTOR,
            action="alert_sla_breached",
            resource=f"alert:{alert.id}",
            details={"due_at": due.isoformat(), "severity": alert.severity},
        )
        if notify:
            dispatch(db, notification_for_sla_breach("alert", alert.id, alert.title, alert.severity, due))

    open_cases = (
        db.query(Case)
        .filter(Case.sla_breached.is_(False), Case.status != CaseStatus.CLOSED)
        .all()
    )
    for case in open_cases:
        due = _as_utc(case.sla_due_at)
        if due is None or due > now:
            continue
        case.sla_breached = True
        db.add(
            CaseTimelineEvent(
                case_id=case.id,
                type=TimelineEventType.SLA_BREACH,
                content={"due_at": due.isoformat()},
                actor=SYSTEM_ACTOR,
            )
        )
        db.commit()
        result.cases_breached.append(case.id)
        append_audit_event(
            db,
            actor=SYSTEM_ACTOR,
            action="case_sla_breached",
            resource=f"case:{case.id}",
            details={"due_at": due.isoformat(), "severity": case.severity},
        )
        if notify:
            dispatch(db, notification_for_sla_breach("case", case.id, case.title, case.severity, due))

    if result.total:
        log.warning(
            "SLA sweep recorded breaches",
            extra={
                "aegis.alerts_breached": len(result.alerts_breached),
                "aegis.cases_breached": len(result.cases_breached),
            },
        )
    return result
