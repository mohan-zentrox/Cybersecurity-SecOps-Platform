"""
FRD ref: FRD-CASE-01..05 — case listing/detail (with immutable timeline),
state-machine-enforced status transitions, comments, and assignment.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_roles
from app.models.case import Case, CaseAlertLink, CaseTimelineEvent, TimelineEventType
from app.models.user import AppRole, User
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
    return CaseDetailOut(
        **CaseOut.model_validate(case).model_dump(),
        timeline=timeline,
        alert_ids=alert_ids,
    )


@router.get("", response_model=list[CaseOut])
def list_cases(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Case]:
    return db.query(Case).order_by(Case.created_at.desc()).all()


@router.get("/{case_id}", response_model=CaseDetailOut)
def get_case(case_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    case = _get_case_or_404(db, case_id)
    return _to_detail(db, case)


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
    db.add(
        CaseTimelineEvent(
            case_id=case.id,
            type=TimelineEventType.STATUS_CHANGE,
            content={"from": previous_status, "to": payload.status},
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
        details={"from": previous_status, "to": payload.status},
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
