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

Supported operators: eq, neq, contains, gt, gte, lt, lte, in, regex, exists.

`evaluate_rule` is pure (no DB access) so it can back both:
  * the persistence-free test harness (POST /api/v1/rules/{id}/test), and
  * the real evaluator that runs against the event store and creates Alerts
    (`run_rule_against_store` below).

Incremental evaluation (FRD-DET-04)
-----------------------------------
A naive evaluator re-reads every stored event for every enabled rule on
every ingest batch, which is O(rules x all events) and degrades badly.
Each rule instead carries an `eval_watermark` — the newest event timestamp
it has already seen. A run only reads events newer than
``watermark - RULE_EVAL_LOOKBACK_SECONDS``; the lookback overlap exists so
a threshold window straddling a batch boundary still fires. Idempotency is
still guaranteed by `dedup_key`, so the overlap cannot double-raise.
"""

import hashlib
import json
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.alert import Alert, AlertStatus
from app.models.rule import DetectionRule
from app.services.normalizer import EventQuery, PostgresJSONBEventStore, StoredEvent
from app.services.notifications import dispatch, notification_for_alert

log = logging.getLogger("aegis.rule_engine")

_SLA_SETTING_BY_SEVERITY = {
    "critical": "SLA_MINUTES_CRITICAL",
    "high": "SLA_MINUTES_HIGH",
    "medium": "SLA_MINUTES_MEDIUM",
    "low": "SLA_MINUTES_LOW",
}


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
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    enrichment: dict[str, Any] = field(default_factory=dict)


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
    if operator == "exists":
        return (actual is not None) == bool(expected)
    if operator == "contains":
        if actual is None:
            return False
        return str(expected) in str(actual)
    if operator == "regex":
        if actual is None:
            return False
        try:
            return re.search(str(expected), str(actual)) is not None
        except re.error as exc:
            raise RuleLogicError(f"Invalid regex {expected!r}: {exc}") from exc
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


def _collect_enrichment(events: list[EvaluatedEvent]) -> dict[str, Any]:
    """Merge any threat.indicator blocks present on the matched events."""
    indicators: dict[int, dict[str, Any]] = {}
    for event in events:
        block = _get_by_path(event.ecs, "threat.indicator") or {}
        for indicator in block.get("indicators", []) or []:
            key = indicator.get("id")
            if key is not None:
                indicators[key] = indicator
    if not indicators:
        return {}
    values = list(indicators.values())
    return {
        "matched": True,
        "count": len(values),
        "max_confidence": max(i.get("confidence", 0) for i in values),
        "indicators": values,
    }


def _as_utc(value: datetime | None) -> datetime | None:
    """Coerce to UTC-aware.

    SQLite does not persist tzinfo on DateTime columns, so a timestamp read
    back from the database is naive even though every value we write is UTC.
    Every cross-value datetime comparison in this module goes through here so
    naive-vs-aware TypeErrors cannot occur on either engine.
    """
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _span(events: list[EvaluatedEvent]) -> tuple[datetime | None, datetime | None]:
    if not events:
        return None, None
    times = [e.timestamp for e in events]
    return min(times), max(times)


def evaluate_rule(rule_logic: dict[str, Any], events: list[EvaluatedEvent]) -> list[RuleMatch]:
    conditions = rule_logic.get("conditions", [])
    match_mode = rule_logic.get("match", "all")
    threshold = rule_logic.get("threshold")

    base_matches = [e for e in events if evaluate_conditions(e.ecs, conditions, match_mode)]
    if not base_matches:
        return []

    if not threshold:
        return [
            RuleMatch(
                group_key=None,
                event_ids=[e.id],
                sample_event_id=e.id,
                first_event_at=e.timestamp,
                last_event_at=e.timestamp,
                enrichment=_collect_enrichment([e]),
            )
            for e in base_matches
        ]

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
            first_at, last_at = _span(burst)
            matches.append(
                RuleMatch(
                    group_key=str(key) if key is not None else None,
                    event_ids=[e.id for e in burst],
                    sample_event_id=burst[-1].id,
                    first_event_at=first_at,
                    last_event_at=last_at,
                    enrichment=_collect_enrichment(burst),
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


def sla_due_for(severity: str, from_time: datetime | None = None) -> datetime:
    """Severity-driven response deadline (FRD-ALERT-05)."""
    settings = get_settings()
    minutes = getattr(settings, _SLA_SETTING_BY_SEVERITY.get(severity, "SLA_MINUTES_MEDIUM"))
    return (from_time or datetime.now(timezone.utc)) + timedelta(minutes=minutes)


@dataclass
class RuleRunResult:
    matches: list[RuleMatch] = field(default_factory=list)
    created_alerts: list[Alert] = field(default_factory=list)
    events_scanned: int = 0


def _evaluation_floor(rule: DetectionRule) -> datetime | None:
    """Lower bound on event timestamps this run needs to read."""
    if rule.eval_watermark is None:
        return None  # first run for this rule: read everything available
    settings = get_settings()
    return _as_utc(rule.eval_watermark) - timedelta(seconds=settings.RULE_EVAL_LOOKBACK_SECONDS)


def run_rule_against_store(db: Session, rule: DetectionRule, *, notify: bool = True) -> RuleRunResult:
    """Evaluate `rule` incrementally against the event store and create Alert rows
    for newly-matched groups.

    Idempotent via `dedup_key`: re-running a rule will not duplicate an alert
    already raised for the same rule + grouping key + event set, which is what
    makes the deliberate lookback overlap safe.
    """
    settings = get_settings()
    store = PostgresJSONBEventStore(db)
    stored_events = store.query_events(
        EventQuery(since=_evaluation_floor(rule), limit=settings.RULE_EVAL_MAX_EVENTS)
    )
    evaluated = stored_events_to_evaluated(stored_events)

    matches = evaluate_rule(rule.logic, evaluated)
    result = RuleRunResult(matches=matches, events_scanned=len(evaluated))

    for match in matches:
        dedup_key = compute_dedup_key(rule.id, match)
        if db.query(Alert).filter(Alert.dedup_key == dedup_key).first():
            continue
        now = datetime.now(timezone.utc)
        alert = Alert(
            rule_id=rule.id,
            title=f"{rule.name} triggered",
            severity=rule.severity,
            status=AlertStatus.NEW,
            dedup_key=dedup_key,
            matched_event_ids=list(match.event_ids),
            enrichment=match.enrichment,
            first_event_at=match.first_event_at,
            sla_due_at=sla_due_for(rule.severity, now),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        result.created_alerts.append(alert)

        if notify:
            dispatch(db, notification_for_alert(alert, rule_name=rule.name))

    # Advance the watermark to the newest event this run actually saw.
    if evaluated:
        newest = max(_as_utc(e.timestamp) for e in evaluated)
        current = _as_utc(rule.eval_watermark)
        if current is None or newest > current:
            rule.eval_watermark = newest
    rule.last_evaluated_at = datetime.now(timezone.utc)
    rule.alert_count = (rule.alert_count or 0) + len(result.created_alerts)
    db.commit()

    if result.created_alerts:
        log.info(
            "detection rule raised alerts",
            extra={
                "aegis.rule_id": rule.id,
                "aegis.rule_name": rule.name,
                "aegis.alerts_created": len(result.created_alerts),
                "aegis.events_scanned": result.events_scanned,
            },
        )
    return result


def run_all_enabled_rules(db: Session, *, notify: bool = True) -> list[Alert]:
    """Evaluate every enabled rule. Used by the ingest path and the worker."""
    created: list[Alert] = []
    for rule in db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all():
        try:
            created.extend(run_rule_against_store(db, rule, notify=notify).created_alerts)
        except RuleLogicError as exc:
            # A single malformed rule must not stop the whole detection pass.
            log.error(
                "detection rule has invalid logic and was skipped",
                extra={"aegis.rule_id": rule.id, "error.message": str(exc)},
            )
    return created
