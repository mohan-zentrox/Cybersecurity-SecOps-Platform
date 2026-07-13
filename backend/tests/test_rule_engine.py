"""
Detection rule engine (FRD-DET-01/02/03): condition matching, threshold-
over-window bursts, the persistence-free test harness endpoint, and the
real evaluator that creates Alert rows (idempotently) from stored events.
"""

from datetime import datetime, timedelta, timezone

from app.models.alert import Alert
from app.services.rule_engine import EvaluatedEvent, evaluate_rule
from tests.conftest import auth_headers

BASE_TS = datetime(2026, 7, 13, 10, 0, 0, tzinfo=timezone.utc)


def _event(offset_seconds: int, **ecs_overrides) -> EvaluatedEvent:
    ecs = {"event": {"action": "logon_failed"}, "source": {"ip": "10.0.0.5"}}
    ecs.update(ecs_overrides)
    return EvaluatedEvent(id=offset_seconds, ecs=ecs, timestamp=BASE_TS + timedelta(seconds=offset_seconds))


# ---------------------------------------------------------------------------
# Pure evaluate_rule() unit tests — no DB, no API.
# ---------------------------------------------------------------------------


def test_simple_condition_match_without_threshold():
    logic = {"conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}]}
    events = [_event(0), _event(1, event={"action": "logon_success"})]
    matches = evaluate_rule(logic, events)
    # Only the logon_failed event should match; each non-threshold match is its own alert.
    assert len(matches) == 1
    assert matches[0].event_ids == [0]


def test_and_vs_or_matching():
    logic_and = {
        "match": "all",
        "conditions": [
            {"field": "event.action", "operator": "eq", "value": "logon_failed"},
            {"field": "source.ip", "operator": "eq", "value": "9.9.9.9"},
        ],
    }
    events = [_event(0)]  # source.ip is 10.0.0.5, not 9.9.9.9
    assert evaluate_rule(logic_and, events) == []

    logic_or = {**logic_and, "match": "any"}
    assert len(evaluate_rule(logic_or, events)) == 1


def test_threshold_over_window_triggers_on_burst():
    logic = {
        "conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}],
        "threshold": {"count": 5, "window_seconds": 300, "group_by": "source.ip"},
    }
    # 5 failed logons from the same source.ip within a 60s span -> one alert.
    events = [_event(i * 10) for i in range(5)]
    matches = evaluate_rule(logic, events)
    assert len(matches) == 1
    assert matches[0].group_key == "10.0.0.5"
    assert len(matches[0].event_ids) == 5


def test_threshold_over_window_does_not_trigger_below_count():
    logic = {
        "conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}],
        "threshold": {"count": 5, "window_seconds": 300, "group_by": "source.ip"},
    }
    events = [_event(i * 10) for i in range(4)]  # only 4 events
    assert evaluate_rule(logic, events) == []


def test_threshold_over_window_does_not_trigger_when_spread_beyond_window():
    logic = {
        "conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}],
        "threshold": {"count": 3, "window_seconds": 60, "group_by": "source.ip"},
    }
    # 3 events but 200s apart each -> no 60s window ever contains 3 of them.
    events = [_event(0), _event(200), _event(400)]
    assert evaluate_rule(logic, events) == []


def test_threshold_groups_are_independent():
    logic = {
        "conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}],
        "threshold": {"count": 3, "window_seconds": 60, "group_by": "source.ip"},
    }
    events = (
        [_event(i * 5, source={"ip": "1.1.1.1"}) for i in range(3)]
        + [_event(i * 5 + 1000, source={"ip": "2.2.2.2"}) for i in range(2)]
    )
    matches = evaluate_rule(logic, events)
    assert len(matches) == 1
    assert matches[0].group_key == "1.1.1.1"


# ---------------------------------------------------------------------------
# API-level: test-harness endpoint (never persists), and the real evaluator.
# ---------------------------------------------------------------------------


def _create_threshold_rule(client, headers) -> int:
    resp = client.post(
        "/api/v1/rules",
        headers=headers,
        json={
            "name": "Brute force login",
            "description": "5+ failed logons from one source IP in 5 minutes",
            "severity": "high",
            "mitre_technique_id": "T1110",
            "logic": {
                "conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}],
                "threshold": {"count": 3, "window_seconds": 300, "group_by": "source.ip"},
            },
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_rule_test_harness_matches_without_persisting_alerts(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    rule_id = _create_threshold_rule(client, headers)

    sample_events = [
        {"event": {"action": "logon_failed"}, "source": {"ip": "10.0.0.9"}, "@timestamp": "2026-07-13T10:00:00Z"},
        {"event": {"action": "logon_failed"}, "source": {"ip": "10.0.0.9"}, "@timestamp": "2026-07-13T10:00:10Z"},
        {"event": {"action": "logon_failed"}, "source": {"ip": "10.0.0.9"}, "@timestamp": "2026-07-13T10:00:20Z"},
    ]
    resp = client.post(f"/api/v1/rules/{rule_id}/test", headers=headers, json={"sample_events": sample_events})
    assert resp.status_code == 200
    body = resp.json()
    assert body["matched_count"] == 1
    assert len(body["matches"][0]["event_ids"]) == 3

    # No alerts should have been created by the test harness.
    assert db.query(Alert).count() == 0


def test_rule_evaluate_creates_alerts_from_stored_events(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    rule_id = _create_threshold_rule(client, headers)

    ingest_payload = {
        "events": [
            {"action": "logon_failed", "src_ip": "10.0.0.9", "timestamp": f"2026-07-13T10:00:{i:02d}Z"}
            for i in range(3)
        ]
    }
    ingest_resp = client.post("/api/v1/events/ingest", headers=headers, json=ingest_payload)
    assert ingest_resp.status_code == 200

    # Ingestion auto-runs enabled rules, so the alert may already exist.
    resp = client.post(f"/api/v1/rules/{rule_id}/evaluate", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["matches_found"] == 1

    assert db.query(Alert).count() == 1
    alert = db.query(Alert).first()
    assert alert.severity == "high"
    assert alert.status == "new"
    assert len(alert.matched_event_ids) == 3


def test_rule_evaluate_is_idempotent(client, detection_engineer_user, db):
    """Re-running evaluate for the same rule/events must not duplicate alerts (dedup_key)."""
    headers = auth_headers(client, "detengineer1")
    rule_id = _create_threshold_rule(client, headers)

    ingest_payload = {
        "events": [
            {"action": "logon_failed", "src_ip": "10.0.0.9", "timestamp": f"2026-07-13T10:00:{i:02d}Z"}
            for i in range(3)
        ]
    }
    client.post("/api/v1/events/ingest", headers=headers, json=ingest_payload)
    assert db.query(Alert).count() == 1

    # Explicitly re-run evaluation multiple times.
    client.post(f"/api/v1/rules/{rule_id}/evaluate", headers=headers)
    client.post(f"/api/v1/rules/{rule_id}/evaluate", headers=headers)

    assert db.query(Alert).count() == 1
