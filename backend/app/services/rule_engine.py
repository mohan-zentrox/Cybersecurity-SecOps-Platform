"""
Detection rule evaluator.

FRD ref: FRD-DET-01/02/03. A DetectionRule.logic document has the shape::

    {
        "match": "all" | "any",        # default "all" — AND vs OR across conditions
        "conditions": [
            {"field": "event.action", "operator": "eq", "value": "logon_failed"}
        ],
        "threshold": {                  # optional — omit for "any single matching event alerts"
            "count": 5,
            "window_seconds": 300,
            "group_by": "source.ip"     # optional — omit to threshold across all matches together
        }
    }

Supported operators: eq, neq, contains, gt, gte, lt, lte, in.

`evaluate_rule` is pure (no DB access) so it can back both:
  * the persistence-free test harness (POST /api/v1/rules/{id}/test), and
  * the real evaluator that runs against the event store and creates Alerts
    (services/rule_engine.py::run_rule_against_store).
"""

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus
from app.models.rule import DetectionRule
from app.services.normalizer import EventQuery, PostgresJSONBEventStore, StoredEvent


class RuleLogicError(Exception):
    pass


@dataclass
class EvaluatedEvent:
    id: Any
    ecs: dict[str, Any]
    timestamp: datetime


@dataclass
class RuleMatch:
    group_key: str | None
    event_ids: list[Any]
    sample_event_id: Any


def _get_by_path(d: dict, path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _apply_operator(operator: str, actual: Any, expected: Any) -> bool:
    if operator == "eq":
        return actual == expected
    if operator == "neq":
        return actual != expected
    if operator == "contains":
        if actual is None:
            return False
        return str(expected) in str(actual)
    if operator == "in":
        if not isinstance(expected, (list, tuple, set)):
            raise RuleLogicError("'in' operator requires a list value")
        return actual in expected
    if operator in ("gt", "gte", "lt", "lte"):
        if actual is None:
            return False
        try:
            a, b = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[operator]
    raise RuleLogicError(f"Unsupported operator: {operator}")


def evaluate_conditions(ecs: dict[str, Any], conditions: list[dict[str, Any]], match: str = "all") -> bool:
    if not conditions:
        raise RuleLogicError("Rule logic must contain at least one condition")
    results = []
    for cond in conditions:
        field_path = cond.get("field")
        operator = cond.get("operator")
        expected = cond.get("value")
        if not field_path or not operator:
            raise RuleLogicError("Each condition requires 'field' and 'operator'")
        actual = _get_by_path(ecs, field_path)
        results.append(_apply_operator(operator, actual, expected))
    return all(results) if match == "all" else any(results)


def _find_threshold_bursts(
    events_sorted: list[EvaluatedEvent], window_seconds: int, count: int
) -> list[list[EvaluatedEvent]]:
    """Sliding-window burst detection: emits one window each time `count` events
    land within any `window_seconds`-wide span, then resets to avoid overlapping
    duplicate triggers for the same sustained burst."""
    triggered: list[list[EvaluatedEvent]] = []
    window: deque[EvaluatedEvent] = deque()
    for ev in events_sorted:
        window.append(ev)
        while window and (ev.timestamp - window[0].timestamp).total_seconds() > window_seconds:
            window.popleft()
        if len(window) >= count:
            triggered.append(list(window))
            window.clear()
    return triggered


def evaluate_rule(rule_logic: dict[str, Any], events: list[EvaluatedEvent]) -> list[RuleMatch]:
    conditions = rule_logic.get("conditions", [])
    match_mode = rule_logic.get("match", "all")
    threshold = rule_logic.get("threshold")

    base_matches = [e for e in events if evaluate_conditions(e.ecs, conditions, match_mode)]
    if not base_matches:
        return []

    if not threshold:
        return [RuleMatch(group_key=None, event_ids=[e.id], sample_event_id=e.id) for e in base_matches]

    window_seconds = threshold.get("window_seconds")
    count = threshold.get("count")
    group_by = threshold.get("group_by")
    if not window_seconds or not count:
        raise RuleLogicError("threshold requires 'count' and 'window_seconds'")

    groups: dict[str | None, list[EvaluatedEvent]] = {}
    for e in base_matches:
        key = _get_by_path(e.ecs, group_by) if group_by else None
        groups.setdefault(key, []).append(e)

    matches: list[RuleMatch] = []
    for key, group_events in groups.items():
        group_events.sort(key=lambda e: e.timestamp)
        for burst in _find_threshold_bursts(group_events, window_seconds, count):
            matches.append(
                RuleMatch(
                    group_key=str(key) if key is not None else None,
                    event_ids=[e.id for e in burst],
                    sample_event_id=burst[-1].id,
                )
            )
    return matches


def stored_events_to_evaluated(events: list[StoredEvent]) -> list[EvaluatedEvent]:
    return [EvaluatedEvent(id=e.id, ecs=e.ecs, timestamp=e.timestamp) for e in events]


def sample_dicts_to_evaluated(samples: list[dict[str, Any]]) -> list[EvaluatedEvent]:
    """Convert raw ECS-shaped sample event dicts (from the test-harness API request) into
    EvaluatedEvent, assigning a stable index-based id since no persisted id exists yet."""
    result = []
    for idx, sample in enumerate(samples):
        ts_raw = _get_by_path(sample, "@timestamp") or sample.get("timestamp")
        if ts_raw:
            try:
                ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)
        result.append(EvaluatedEvent(id=idx, ecs=sample, timestamp=ts))
    return result


def compute_dedup_key(rule_id: int, match: RuleMatch) -> str:
    payload = json.dumps(
        {"rule_id": rule_id, "group_key": match.group_key, "event_ids": sorted(map(str, match.event_ids))},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


@dataclass
class RuleRunResult:
    matches: list[RuleMatch] = field(default_factory=list)
    created_alerts: list[Alert] = field(default_factory=list)


def run_rule_against_store(db: Session, rule: DetectionRule) -> RuleRunResult:
    """Evaluate `rule` against every stored normalized event and create Alert rows
    for newly-matched groups (idempotent via dedup_key — re-running a rule will not
    duplicate an alert already raised for the same rule + grouping key + event set)."""
    store = PostgresJSONBEventStore(db)
    stored_events = store.query_events(EventQuery())
    evaluated = stored_events_to_evaluated(stored_events)

    matches = evaluate_rule(rule.logic, evaluated)
    result = RuleRunResult(matches=matches)

    for match in matches:
        dedup_key = compute_dedup_key(rule.id, match)
        existing = db.query(Alert).filter(Alert.dedup_key == dedup_key).first()
        if existing:
            continue
        alert = Alert(
            rule_id=rule.id,
            title=f"{rule.name} triggered",
            severity=rule.severity,
            status=AlertStatus.NEW,
            dedup_key=dedup_key,
            matched_event_ids=list(match.event_ids),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        result.created_alerts.append(alert)

    return result
