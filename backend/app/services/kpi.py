"""
SOC KPI aggregation.

FRD ref: FRD-KPI-01/02 — the metrics a SOC manager actually reports on:

  * **MTTD** (mean time to detect) — ``alert.created_at - alert.first_event_at``.
    How long telemetry sat in the platform before a rule fired on it.
  * **MTTA** (mean time to acknowledge) — ``acknowledged_at - created_at``.
  * **MTTR** (mean time to resolve) — ``closed_at - created_at``.
  * **SLA breach rate** — breached / total, for alerts and cases.
  * **Alert volume** — by severity, by status, by rule, bucketed by day.
  * **Analyst workload** — open alerts and cases per assignee.

Everything is computed with aggregate SQL over the reporting window rather
than by shipping row-level data to the client (FRD-KPI-02). At the volumes
where these queries stop being cheap, the same functions become the body
of a scheduled materialization job (FRD-KPI-03) — the API contract does
not change.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import case as sql_case
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus
from app.models.case import Case, CaseStatus
from app.models.event import DeadLetterEvent, NormalizedEvent
from app.models.rule import DetectionRule
from app.models.user import User


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _mean_minutes(pairs: list[tuple[datetime | None, datetime | None]]) -> float | None:
    """Mean gap in minutes across (start, end) pairs, ignoring incomplete ones."""
    deltas = [
        (_as_utc(end) - _as_utc(start)).total_seconds() / 60.0
        for start, end in pairs
        if start is not None and end is not None
    ]
    if not deltas:
        return None
    # Clock skew on ingested telemetry can produce a negative gap; clamp rather
    # than letting one bad producer drag the mean below zero.
    deltas = [max(d, 0.0) for d in deltas]
    return round(sum(deltas) / len(deltas), 2)


def _percentile_minutes(pairs: list[tuple[datetime | None, datetime | None]], pct: float) -> float | None:
    deltas = sorted(
        max((_as_utc(end) - _as_utc(start)).total_seconds() / 60.0, 0.0)
        for start, end in pairs
        if start is not None and end is not None
    )
    if not deltas:
        return None
    index = min(int(round((pct / 100.0) * (len(deltas) - 1))), len(deltas) - 1)
    return round(deltas[index], 2)


@dataclass
class Window:
    start: datetime
    end: datetime
    label: str


def parse_window(window: str) -> Window:
    """Parse a window spec like `24h`, `7d`, `30d` into an absolute range."""
    now = datetime.now(timezone.utc)
    unit = window[-1:].lower()
    try:
        amount = int(window[:-1])
    except ValueError as exc:
        raise ValueError(f"Invalid window {window!r}; expected forms like '24h', '7d', '30d'") from exc
    if amount <= 0:
        raise ValueError("Window amount must be positive")
    if unit == "h":
        delta = timedelta(hours=amount)
    elif unit == "d":
        delta = timedelta(days=amount)
    else:
        raise ValueError(f"Invalid window unit {unit!r}; expected 'h' or 'd'")
    return Window(start=now - delta, end=now, label=window)


def _counts_by(db: Session, model, column, since: datetime) -> dict[str, int]:
    rows = (
        db.query(column, func.count(model.id))
        .filter(model.created_at >= since)
        .group_by(column)
        .all()
    )
    return {str(key): int(count) for key, count in rows}


def alert_metrics(db: Session, window: Window) -> dict[str, Any]:
    alerts = db.query(Alert).filter(Alert.created_at >= window.start).all()
    total = len(alerts)
    breached = sum(1 for a in alerts if a.sla_breached)
    closed = [a for a in alerts if a.status == AlertStatus.CLOSED]

    return {
        "total": total,
        "open": sum(1 for a in alerts if a.status != AlertStatus.CLOSED),
        "closed": len(closed),
        "by_severity": _counts_by(db, Alert, Alert.severity, window.start),
        "by_status": _counts_by(db, Alert, Alert.status, window.start),
        "sla_breached": breached,
        "sla_breach_rate": round(breached / total, 4) if total else 0.0,
        "mttd_minutes": _mean_minutes([(a.first_event_at, a.created_at) for a in alerts]),
        "mtta_minutes": _mean_minutes([(a.created_at, a.acknowledged_at) for a in alerts]),
        "mttr_minutes": _mean_minutes([(a.created_at, a.closed_at) for a in alerts]),
        "mttr_p95_minutes": _percentile_minutes([(a.created_at, a.closed_at) for a in alerts], 95),
    }


def case_metrics(db: Session, window: Window) -> dict[str, Any]:
    cases = db.query(Case).filter(Case.created_at >= window.start).all()
    total = len(cases)
    breached = sum(1 for c in cases if c.sla_breached)
    resolutions: dict[str, int] = {}
    for c in cases:
        if c.resolution:
            resolutions[c.resolution] = resolutions.get(c.resolution, 0) + 1

    return {
        "total": total,
        "open": sum(1 for c in cases if c.status != CaseStatus.CLOSED),
        "closed": sum(1 for c in cases if c.status == CaseStatus.CLOSED),
        "by_severity": _counts_by(db, Case, Case.severity, window.start),
        "by_status": _counts_by(db, Case, Case.status, window.start),
        "by_resolution": resolutions,
        "sla_breached": breached,
        "sla_breach_rate": round(breached / total, 4) if total else 0.0,
        "mttr_minutes": _mean_minutes([(c.created_at, c.closed_at) for c in cases]),
        "mttr_p95_minutes": _percentile_minutes([(c.created_at, c.closed_at) for c in cases], 95),
    }


def alerts_by_rule(db: Session, window: Window, limit: int = 10) -> list[dict[str, Any]]:
    """Noisiest rules in the window — the list a detection engineer tunes from."""
    rows = (
        db.query(DetectionRule.id, DetectionRule.name, DetectionRule.severity, func.count(Alert.id))
        .join(Alert, Alert.rule_id == DetectionRule.id)
        .filter(Alert.created_at >= window.start)
        .group_by(DetectionRule.id, DetectionRule.name, DetectionRule.severity)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )
    return [
        {"rule_id": rid, "rule_name": name, "severity": severity, "alert_count": int(count)}
        for rid, name, severity, count in rows
    ]


def alert_volume_series(db: Session, window: Window) -> list[dict[str, Any]]:
    """Daily alert counts across the window, zero-filled so the chart has no gaps."""
    alerts = db.query(Alert.created_at, Alert.severity).filter(Alert.created_at >= window.start).all()

    buckets: dict[str, dict[str, int]] = {}
    day = window.start.replace(hour=0, minute=0, second=0, microsecond=0)
    while day <= window.end:
        buckets[day.date().isoformat()] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        day += timedelta(days=1)

    for created_at, severity in alerts:
        key = _as_utc(created_at).date().isoformat()
        if key in buckets and severity in buckets[key]:
            buckets[key][severity] += 1

    return [{"date": date, **counts, "total": sum(counts.values())} for date, counts in sorted(buckets.items())]


def analyst_workload(db: Session) -> list[dict[str, Any]]:
    """Open alerts and cases per assignee — who is underwater right now."""
    users = db.query(User).filter(User.is_active.is_(True)).all()
    alert_rows = dict(
        db.query(Alert.assigned_to, func.count(Alert.id))
        .filter(Alert.assigned_to.isnot(None), Alert.status != AlertStatus.CLOSED)
        .group_by(Alert.assigned_to)
        .all()
    )
    case_rows = dict(
        db.query(Case.assigned_to, func.count(Case.id))
        .filter(Case.assigned_to.isnot(None), Case.status != CaseStatus.CLOSED)
        .group_by(Case.assigned_to)
        .all()
    )
    breach_rows = dict(
        db.query(Case.assigned_to, func.count(Case.id))
        .filter(Case.assigned_to.isnot(None), Case.sla_breached.is_(True), Case.status != CaseStatus.CLOSED)
        .group_by(Case.assigned_to)
        .all()
    )

    workload = [
        {
            "user_id": u.id,
            "username": u.username,
            "role": u.role,
            "open_alerts": int(alert_rows.get(u.id, 0)),
            "open_cases": int(case_rows.get(u.id, 0)),
            "breached_cases": int(breach_rows.get(u.id, 0)),
        }
        for u in users
    ]
    workload.sort(key=lambda w: (w["open_cases"] + w["open_alerts"]), reverse=True)
    return workload


def ingestion_metrics(db: Session, window: Window) -> dict[str, Any]:
    accepted = db.query(func.count(NormalizedEvent.id)).filter(
        NormalizedEvent.ingested_at >= window.start
    ).scalar()
    dead = db.query(func.count(DeadLetterEvent.id)).filter(
        DeadLetterEvent.received_at >= window.start
    ).scalar()
    threat = db.query(func.count(NormalizedEvent.id)).filter(
        NormalizedEvent.ingested_at >= window.start, NormalizedEvent.threat_matched.is_(True)
    ).scalar()
    total = int(accepted) + int(dead)
    return {
        "events_normalized": int(accepted),
        "events_dead_lettered": int(dead),
        "dead_letter_rate": round(int(dead) / total, 4) if total else 0.0,
        "events_with_threat_match": int(threat),
    }


def detection_coverage(db: Session) -> dict[str, Any]:
    """Rule inventory and MITRE ATT&CK technique coverage."""
    total, enabled = db.query(
        func.count(DetectionRule.id),
        func.sum(sql_case((DetectionRule.enabled.is_(True), 1), else_=0)),
    ).one()
    techniques = [
        t
        for (t,) in db.query(DetectionRule.mitre_technique_id)
        .filter(DetectionRule.mitre_technique_id.isnot(None), DetectionRule.enabled.is_(True))
        .distinct()
        .all()
    ]
    return {
        "rules_total": int(total or 0),
        "rules_enabled": int(enabled or 0),
        "rules_disabled": int(total or 0) - int(enabled or 0),
        "mitre_techniques_covered": sorted(techniques),
        "mitre_technique_count": len(techniques),
    }


def kpi_summary(db: Session, window_spec: str = "7d") -> dict[str, Any]:
    """The single payload behind GET /api/v1/kpis/summary."""
    window = parse_window(window_spec)
    return {
        "window": window.label,
        "window_start": window.start.isoformat(),
        "window_end": window.end.isoformat(),
        "alerts": alert_metrics(db, window),
        "cases": case_metrics(db, window),
        "ingestion": ingestion_metrics(db, window),
        "detection": detection_coverage(db),
        "top_rules": alerts_by_rule(db, window),
        "volume_series": alert_volume_series(db, window),
        "workload": analyst_workload(db),
    }
