"""
FRD ref: FRD-DET-01..04 — full detection-rule lifecycle: create, list,
get, update, enable/disable, delete, a persistence-free test harness, and
the real evaluator that creates Alerts from stored normalized events.

Editing a rule resets its evaluation watermark so the new logic is applied
to history rather than only to events that arrive afterwards — otherwise a
corrected rule would silently miss everything already ingested.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.models.user import AppRole, User
from app.schemas.rule import (
    RuleCreate,
    RuleEvaluateResponse,
    RuleOut,
    RuleTestMatchOut,
    RuleTestRequest,
    RuleTestResponse,
    RuleToggle,
    RuleUpdate,
)
from app.services.audit_chain import append_audit_event
from app.services.rule_engine import (
    RuleLogicError,
    evaluate_rule,
    run_rule_against_store,
    sample_dicts_to_evaluated,
)

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


@router.get("", response_model=Page[RuleOut])
def list_rules(
    enabled: bool | None = None,
    severity: str | None = None,
    search: str | None = Query(default=None, max_length=200),
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[RuleOut]:
    query = db.query(DetectionRule)
    if enabled is not None:
        query = query.filter(DetectionRule.enabled.is_(enabled))
    if severity:
        query = query.filter(DetectionRule.severity == severity)
    if search:
        query = query.filter(DetectionRule.name.ilike(f"%{search}%"))

    rows, total = paginate(db, query.order_by(DetectionRule.id.asc()), params)
    return Page[RuleOut](
        items=[RuleOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/{rule_id}", response_model=RuleOut)
def get_rule(
    rule_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> DetectionRule:
    return _get_rule_or_404(db, rule_id)


@router.patch("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    current_user: User = Depends(require_roles(*_RULE_AUTHORS)),
    db: Session = Depends(get_db),
) -> DetectionRule:
    rule = _get_rule_or_404(db, rule_id)
    changes: dict[str, object] = {}

    if payload.name is not None:
        changes["name"] = payload.name
        rule.name = payload.name
    if payload.description is not None:
        rule.description = payload.description
        changes["description"] = "updated"
    if payload.severity is not None:
        changes["severity"] = payload.severity
        rule.severity = payload.severity
    if payload.mitre_technique_id is not None:
        changes["mitre_technique_id"] = payload.mitre_technique_id
        rule.mitre_technique_id = payload.mitre_technique_id
    if payload.enabled is not None:
        changes["enabled"] = payload.enabled
        rule.enabled = payload.enabled
    if payload.logic is not None:
        rule.logic = payload.logic.model_dump()
        changes["logic"] = "updated"
        # New logic must be applied to history, not just to future events.
        rule.eval_watermark = None

    db.commit()
    db.refresh(rule)

    if changes:
        append_audit_event(
            db,
            actor=current_user.username,
            action="rule_updated",
            resource=f"rule:{rule.id}",
            details=changes,
        )
    return rule


@router.patch("/{rule_id}/enabled", response_model=RuleOut)
def toggle_rule(
    rule_id: int,
    payload: RuleToggle,
    current_user: User = Depends(require_roles(*_RULE_AUTHORS)),
    db: Session = Depends(get_db),
) -> DetectionRule:
    rule = _get_rule_or_404(db, rule_id)
    rule.enabled = payload.enabled
    db.commit()
    db.refresh(rule)

    append_audit_event(
        db,
        actor=current_user.username,
        action="rule_enabled" if payload.enabled else "rule_disabled",
        resource=f"rule:{rule.id}",
        details={"name": rule.name},
    )
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: int,
    current_user: User = Depends(require_roles(*_RULE_AUTHORS)),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a rule that has never fired. A rule with alerts attached must be
    disabled instead — deleting it would orphan the alerts that cite it as
    the reason they exist."""
    rule = _get_rule_or_404(db, rule_id)
    alert_count = db.query(Alert).filter(Alert.rule_id == rule.id).count()
    if alert_count:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Rule has {alert_count} alert(s) referencing it; disable it instead of deleting "
                "so the alert history stays explicable"
            ),
        )

    name = rule.name
    db.delete(rule)
    db.commit()

    append_audit_event(
        db,
        actor=current_user.username,
        action="rule_deleted",
        resource=f"rule:{rule_id}",
        details={"name": name},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
    try:
        matches = evaluate_rule(rule.logic, evaluated)
    except RuleLogicError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

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
    full_rescan: bool = Query(default=False, description="Ignore the watermark and re-read all history"),
    current_user: User = Depends(require_roles(*_RULE_OPERATORS)),
    db: Session = Depends(get_db),
) -> RuleEvaluateResponse:
    """Run a rule against the persisted event store and create Alerts for new matches."""
    rule = _get_rule_or_404(db, rule_id)
    if full_rescan:
        rule.eval_watermark = None
        db.commit()

    try:
        result = run_rule_against_store(db, rule)
    except RuleLogicError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

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
        events_scanned=result.events_scanned,
    )
