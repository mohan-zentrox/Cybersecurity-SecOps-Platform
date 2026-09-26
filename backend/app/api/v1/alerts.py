"""
FRD ref: FRD-ALERT-01/02/03/05 — alert listing with filters and paging,
state-machine-enforced status transitions, bulk triage, assignment, and
promotion of one or more alerts into a Case.

Status transitions maintain the lifecycle timestamps the KPI layer reads
(`acknowledged_at` on the first move off `new`, `closed_at` on reaching
the terminal state), so MTTA/MTTR never have to be reconstructed from the
audit log.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.alert import Alert, AlertStatus
from app.models.case import Case, CaseAlertLink, CaseStatus, CaseTimelineEvent, TimelineEventType
from app.models.rule import Severity
from app.models.user import AppRole, User
from app.schemas.alert import (
    AlertAssign,
    AlertBulkResult,
    AlertBulkStatusUpdate,
    AlertOut,
    AlertStatusUpdate,
    PromoteToCaseRequest,
)
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


def _validate_assignee(db: Session, user_id: int | None) -> None:
    if user_id is None:
        return
    assignee = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if assignee is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Assignee is not an active user"
        )


def _apply_transition(alert: Alert, target: str) -> None:
    """Move the alert and stamp the lifecycle timestamps the KPI layer reads."""
    validate_transition(alert.status, target)
    now = datetime.now(timezone.utc)
    if alert.status == AlertStatus.NEW and alert.acknowledged_at is None:
        alert.acknowledged_at = now
    if target == AlertStatus.CLOSED:
        alert.closed_at = now
    alert.status = target


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    assigned_to: int | None = None,
    rule_id: int | None = None,
    sla_breached: bool | None = None,
    unassigned: bool | None = None,
    search: str | None = Query(default=None, max_length=200),
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[AlertOut]:
    query = db.query(Alert)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    if severity:
        query = query.filter(Alert.severity == severity)
    if assigned_to is not None:
        query = query.filter(Alert.assigned_to == assigned_to)
    if unassigned:
        query = query.filter(Alert.assigned_to.is_(None))
    if rule_id is not None:
        query = query.filter(Alert.rule_id == rule_id)
    if sla_breached is not None:
        query = query.filter(Alert.sla_breached.is_(sla_breached))
    if search:
        query = query.filter(Alert.title.ilike(f"%{search}%"))

    rows, total = paginate(db, query.order_by(Alert.created_at.desc()), params)
    return Page[AlertOut](
        items=[AlertOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Alert:
    return _get_alert_or_404(db, alert_id)


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _get_alert_or_404(db, alert_id)
    previous_status = alert.status
    try:
        _apply_transition(alert, payload.status)
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

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


@router.post("/bulk/status", response_model=AlertBulkResult)
def bulk_update_status(
    payload: AlertBulkStatusUpdate,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
) -> AlertBulkResult:
    """Triage many alerts at once; per-alert failures are reported, not fatal."""
    updated: list[int] = []
    failed: dict[str, str] = {}

    alerts = db.query(Alert).filter(Alert.id.in_(payload.alert_ids)).all()
    found = {a.id for a in alerts}
    for missing in set(payload.alert_ids) - found:
        failed[str(missing)] = "Alert not found"

    for alert in alerts:
        previous_status = alert.status
        try:
            _apply_transition(alert, payload.status)
        except InvalidTransitionError as exc:
            failed[str(alert.id)] = str(exc)
            continue
        updated.append(alert.id)
        append_audit_event(
            db,
            actor=current_user.username,
            action="alert_status_changed",
            resource=f"alert:{alert.id}",
            details={"from": previous_status, "to": payload.status, "bulk": True},
        )
    db.commit()
    return AlertBulkResult(updated=updated, failed=failed)


@router.patch("/{alert_id}/assign", response_model=AlertOut)
def assign_alert(
    alert_id: int,
    payload: AlertAssign,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _get_alert_or_404(db, alert_id)
    _validate_assignee(db, payload.assigned_to)
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
        # Promotion is triage: an alert that has become a case is under
        # investigation, so advance it rather than leaving it sitting in `new`.
        if alert.status == AlertStatus.NEW:
            try:
                _apply_transition(alert, AlertStatus.INVESTIGATING)
            except InvalidTransitionError:  # pragma: no cover - `new` always permits this
                pass
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
