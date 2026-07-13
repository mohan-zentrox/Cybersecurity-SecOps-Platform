"""
FRD ref: FRD-DET-01/02/03 — detection rule CRUD (subset: create/list/get),
a persistence-free test harness, and the real evaluator that creates
Alerts from stored normalized events.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_roles
from app.models.rule import DetectionRule
from app.models.user import AppRole, User
from app.schemas.rule import (
    RuleCreate,
    RuleEvaluateResponse,
    RuleOut,
    RuleTestMatchOut,
    RuleTestRequest,
    RuleTestResponse,
)
from app.services.audit_chain import append_audit_event
from app.services.rule_engine import evaluate_rule, run_rule_against_store, sample_dicts_to_evaluated

router = APIRouter(prefix="/rules", tags=["rules"])

_RULE_AUTHORS = (AppRole.DETECTION_ENGINEER, AppRole.ADMIN)
_RULE_OPERATORS = (AppRole.ANALYST, AppRole.DETECTION_ENGINEER, AppRole.ADMIN)


def _get_rule_or_404(db: Session, rule_id: int) -> DetectionRule:
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@router.post("", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: RuleCreate,
    current_user: User = Depends(require_roles(*_RULE_AUTHORS)),
    db: Session = Depends(get_db),
) -> DetectionRule:
    rule = DetectionRule(
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
        mitre_technique_id=payload.mitre_technique_id,
        logic=payload.logic.model_dump(),
        enabled=payload.enabled,
        created_by=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    append_audit_event(
        db,
        actor=current_user.username,
        action="rule_created",
        resource=f"rule:{rule.id}",
        details={"name": rule.name, "severity": rule.severity},
    )
    return rule


@router.get("", response_model=list[RuleOut])
def list_rules(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[DetectionRule]:
    return db.query(DetectionRule).order_by(DetectionRule.id.asc()).all()


@router.get("/{rule_id}", response_model=RuleOut)
def get_rule(
    rule_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> DetectionRule:
    return _get_rule_or_404(db, rule_id)


@router.post("/{rule_id}/test", response_model=RuleTestResponse)
def test_rule(
    rule_id: int,
    payload: RuleTestRequest,
    current_user: User = Depends(require_roles(*_RULE_OPERATORS)),
    db: Session = Depends(get_db),
) -> RuleTestResponse:
    """Run a rule against a caller-supplied sample event set. Never persists alerts."""
    rule = _get_rule_or_404(db, rule_id)
    evaluated = sample_dicts_to_evaluated(payload.sample_events)
    matches = evaluate_rule(rule.logic, evaluated)

    return RuleTestResponse(
        rule_id=rule.id,
        matched_count=len(matches),
        matches=[
            RuleTestMatchOut(group_key=m.group_key, event_ids=m.event_ids, sample_event_id=m.sample_event_id)
            for m in matches
        ],
    )


@router.post("/{rule_id}/evaluate", response_model=RuleEvaluateResponse)
def evaluate_rule_against_store(
    rule_id: int,
    current_user: User = Depends(require_roles(*_RULE_OPERATORS)),
    db: Session = Depends(get_db),
) -> RuleEvaluateResponse:
    """Run a rule against the persisted event store and create Alerts for new matches."""
    rule = _get_rule_or_404(db, rule_id)
    result = run_rule_against_store(db, rule)

    if result.created_alerts:
        append_audit_event(
            db,
            actor=current_user.username,
            action="rule_evaluated_alerts_created",
            resource=f"rule:{rule.id}",
            details={"alert_ids": [a.id for a in result.created_alerts]},
        )

    return RuleEvaluateResponse(
        rule_id=rule.id,
        matches_found=len(result.matches),
        alerts_created=len(result.created_alerts),
        alert_ids=[a.id for a in result.created_alerts],
    )
