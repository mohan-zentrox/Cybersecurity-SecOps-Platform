"""
FRD ref: FRD-CASE-01..06 — case listing with filters/paging, detail with
the immutable timeline, state-machine-enforced status transitions,
comments, and assignment.

Closing a case requires a `resolution` (FRD-CASE-06). Without it "closed"
carries no analytical meaning, and false-positive rate — the number that
drives detection-rule tuning — cannot be computed.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.case import Case, CaseAlertLink, CaseStatus, CaseTimelineEvent, TimelineEventType
from app.models.user import AppRole, User
from app.models.vulnerability import Vulnerability
from app.schemas.case import CaseAssign, CaseCommentCreate, CaseDetailOut, CaseOut, CaseStatusUpdate
from app.services.audit_chain import append_audit_event
from app.services.state_machine import InvalidTransitionError, validate_transition

router = APIRouter(prefix="/cases", tags=["cases"])

_ANALYST_PLUS = (AppRole.ANALYST, AppRole.DETECTION_ENGINEER, AppRole.ADMIN)


def _get_case_or_404(db: Session, case_id: int) -> Case:
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return case


def _validate_assignee(db: Session, user_id: int | None) -> None:
    if user_id is None:
        return
    if db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first() is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Assignee is not an active user"
        )


def _to_detail(db: Session, case: Case) -> CaseDetailOut:
    timeline = (
        db.query(CaseTimelineEvent)
        .filter(CaseTimelineEvent.case_id == case.id)
        .order_by(CaseTimelineEvent.id.asc())
        .all()
    )
    alert_ids = [
        link.alert_id for link in db.query(CaseAlertLink).filter(CaseAlertLink.case_id == case.id).all()
    ]
    vulnerability_ids = [
        v.id for v in db.query(Vulnerability).filter(Vulnerability.case_id == case.id).all()
    ]
    return CaseDetailOut(
        **CaseOut.model_validate(case).model_dump(),
        timeline=timeline,
        alert_ids=alert_ids,
        vulnerability_ids=vulnerability_ids,
    )


@router.get("", response_model=Page[CaseOut])
def list_cases(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    assigned_to: int | None = None,
    sla_breached: bool | None = None,
    resolution: str | None = None,
    search: str | None = Query(default=None, max_length=200),
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[CaseOut]:
    query = db.query(Case)
    if status_filter:
        query = query.filter(Case.status == status_filter)
    if severity:
        query = query.filter(Case.severity == severity)
    if assigned_to is not None:
        query = query.filter(Case.assigned_to == assigned_to)
    if sla_breached is not None:
        query = query.filter(Case.sla_breached.is_(sla_breached))
    if resolution:
        query = query.filter(Case.resolution == resolution)
    if search:
        query = query.filter(Case.title.ilike(f"%{search}%"))

    rows, total = paginate(db, query.order_by(Case.created_at.desc()), params)
    return Page[CaseOut](
        items=[CaseOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/{case_id}", response_model=CaseDetailOut)
def get_case(case_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _to_detail(db, _get_case_or_404(db, case_id))


@router.patch("/{case_id}/status", response_model=CaseDetailOut)
def update_case_status(
    case_id: int,
    payload: CaseStatusUpdate,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
):
    case = _get_case_or_404(db, case_id)
    try:
        validate_transition(case.status, payload.status)
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    previous_status = case.status
    case.status = payload.status
    content: dict[str, object] = {"from": previous_status, "to": payload.status}

    if payload.status == CaseStatus.CLOSED:
        case.closed_at = datetime.now(timezone.utc)
        case.resolution = payload.resolution
        case.resolution_summary = payload.resolution_summary
        content["resolution"] = payload.resolution
        if payload.resolution_summary:
            content["resolution_summary"] = payload.resolution_summary

    db.add(
        CaseTimelineEvent(
            case_id=case.id,
            type=TimelineEventType.STATUS_CHANGE,
            content=content,
            actor=current_user.username,
        )
    )
    db.commit()
    db.refresh(case)

    append_audit_event(
        db,
        actor=current_user.username,
        action="case_status_changed",
        resource=f"case:{case.id}",
        details=content,
    )
    return _to_detail(db, case)


@router.post("/{case_id}/comments", response_model=CaseDetailOut, status_code=status.HTTP_201_CREATED)
def add_case_comment(
    case_id: int,
    payload: CaseCommentCreate,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
):
    case = _get_case_or_404(db, case_id)
    db.add(
        CaseTimelineEvent(
            case_id=case.id,
            type=TimelineEventType.COMMENT,
            content={"comment": payload.comment},
            actor=current_user.username,
        )
    )
    db.commit()

    append_audit_event(
        db, actor=current_user.username, action="case_comment_added", resource=f"case:{case.id}", details={}
    )
    return _to_detail(db, case)


@router.patch("/{case_id}/assign", response_model=CaseDetailOut)
def assign_case(
    case_id: int,
    payload: CaseAssign,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
):
    case = _get_case_or_404(db, case_id)
    _validate_assignee(db, payload.assigned_to)
    case.assigned_to = payload.assigned_to
    db.add(
        CaseTimelineEvent(
            case_id=case.id,
            type=TimelineEventType.ASSIGNMENT,
            content={"assigned_to": payload.assigned_to},
            actor=current_user.username,
        )
    )
    db.commit()
    db.refresh(case)

    append_audit_event(
        db,
        actor=current_user.username,
        action="case_assigned",
        resource=f"case:{case.id}",
        details={"assigned_to": payload.assigned_to},
    )
    return _to_detail(db, case)
