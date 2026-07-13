"""
FRD ref: FRD-ALERT-01/02/03 — alert listing, state-machine-enforced status
transitions, assignment, and promotion of one or more alerts into a Case.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, get_db, require_roles
from app.models.alert import Alert
from app.models.case import Case, CaseAlertLink, CaseStatus, CaseTimelineEvent, TimelineEventType
from app.models.rule import Severity
from app.models.user import AppRole, User
from app.schemas.alert import AlertAssign, AlertOut, AlertStatusUpdate, PromoteToCaseRequest
from app.schemas.case import CaseOut
from app.services.audit_chain import append_audit_event
from app.services.state_machine import InvalidTransitionError, validate_transition

router = APIRouter(prefix="/alerts", tags=["alerts"])

_ANALYST_PLUS = (AppRole.ANALYST, AppRole.DETECTION_ENGINEER, AppRole.ADMIN)

_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
_SLA_MINUTES_BY_SEVERITY = {
    Severity.CRITICAL: "SLA_MINUTES_CRITICAL",
    Severity.HIGH: "SLA_MINUTES_HIGH",
    Severity.MEDIUM: "SLA_MINUTES_MEDIUM",
    Severity.LOW: "SLA_MINUTES_LOW",
}


def _get_alert_or_404(db: Session, alert_id: int) -> Alert:
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.get("", response_model=list[AlertOut])
def list_alerts(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Alert]:
    return db.query(Alert).order_by(Alert.created_at.desc()).all()


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Alert:
    return _get_alert_or_404(db, alert_id)


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _get_alert_or_404(db, alert_id)
    try:
        validate_transition(alert.status, payload.status)
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    previous_status = alert.status
    alert.status = payload.status
    db.commit()
    db.refresh(alert)

    append_audit_event(
        db,
        actor=current_user.username,
        action="alert_status_changed",
        resource=f"alert:{alert.id}",
        details={"from": previous_status, "to": payload.status},
    )
    return alert


@router.patch("/{alert_id}/assign", response_model=AlertOut)
def assign_alert(
    alert_id: int,
    payload: AlertAssign,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _get_alert_or_404(db, alert_id)
    alert.assigned_to = payload.assigned_to
    db.commit()
    db.refresh(alert)

    append_audit_event(
        db,
        actor=current_user.username,
        action="alert_assigned",
        resource=f"alert:{alert.id}",
        details={"assigned_to": payload.assigned_to},
    )
    return alert


@router.post("/promote", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def promote_alerts_to_case(
    payload: PromoteToCaseRequest,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
) -> Case:
    if not payload.alert_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="alert_ids must not be empty")

    alerts = db.query(Alert).filter(Alert.id.in_(payload.alert_ids)).all()
    if len(alerts) != len(set(payload.alert_ids)):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or more alerts not found")

    highest_severity = max((a.severity for a in alerts), key=lambda s: _SEVERITY_RANK.get(s, 0))
    settings = get_settings()
    sla_minutes = getattr(settings, _SLA_MINUTES_BY_SEVERITY[highest_severity])
    now = datetime.now(timezone.utc)

    case = Case(
        title=payload.title or f"Case: {alerts[0].title}",
        severity=highest_severity,
        status=CaseStatus.NEW,
        sla_due_at=now + timedelta(minutes=sla_minutes),
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    db.add(
        CaseTimelineEvent(
            case_id=case.id,
            type=TimelineEventType.CREATED,
            content={"promoted_from_alert_ids": payload.alert_ids},
            actor=current_user.username,
        )
    )
    for alert in alerts:
        db.add(CaseAlertLink(case_id=case.id, alert_id=alert.id))
        db.add(
            CaseTimelineEvent(
                case_id=case.id,
                type=TimelineEventType.ALERT_LINKED,
                content={"alert_id": alert.id},
                actor=current_user.username,
            )
        )
    db.commit()
    db.refresh(case)

    append_audit_event(
        db,
        actor=current_user.username,
        action="alerts_promoted_to_case",
        resource=f"case:{case.id}",
        details={"alert_ids": payload.alert_ids},
    )
    return case
