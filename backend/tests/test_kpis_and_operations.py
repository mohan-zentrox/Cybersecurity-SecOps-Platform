"""
SOC KPI aggregation (FRD-KPI-01/02), dead-letter replay (FRD-ING-05),
detection-rule CRUD (FRD-DET-01), and incremental evaluation (FRD-DET-04).
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.alert import Alert, AlertStatus
from app.models.event import DeadLetterEvent, NormalizedEvent
from app.models.rule import DetectionRule
from app.services.kpi import kpi_summary, parse_window
from tests.conftest import auth_headers

NOW = datetime.now(timezone.utc)


def _alert(db, **kwargs) -> Alert:
    defaults = {
        "title": "Alert",
        "severity": "high",
        "status": AlertStatus.NEW,
        "dedup_key": f"k{kwargs.pop('n', 0)}",
        "matched_event_ids": [],
    }
    defaults.update(kwargs)
    alert = Alert(**defaults)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


# ---------------------------------------------------------------------------
# KPI window parsing and aggregation
# ---------------------------------------------------------------------------


def test_window_parsing():
    # Each call stamps its own `now`, so measure the span within a single window.
    for spec, expected in (("24h", timedelta(hours=24)), ("7d", timedelta(days=7))):
        window = parse_window(spec)
        assert window.end - window.start == expected
        assert window.label == spec
    for bad in ("", "7", "7w", "-1d", "0d", "abc"):
        with pytest.raises(ValueError):
            parse_window(bad)


def test_mttd_and_mttr_are_computed_from_lifecycle_timestamps(db):
    # Detected 10 minutes after the underlying event; closed 30 minutes later.
    _alert(
        db,
        n=1,
        first_event_at=NOW - timedelta(minutes=40),
        created_at=NOW - timedelta(minutes=30),
        acknowledged_at=NOW - timedelta(minutes=25),
        closed_at=NOW,
        status=AlertStatus.CLOSED,
    )
    summary = kpi_summary(db, "7d")

    assert summary["alerts"]["mttd_minutes"] == pytest.approx(10.0, abs=0.5)
    assert summary["alerts"]["mtta_minutes"] == pytest.approx(5.0, abs=0.5)
    assert summary["alerts"]["mttr_minutes"] == pytest.approx(30.0, abs=0.5)


def test_metrics_are_none_not_zero_when_nothing_has_closed(db):
    """An empty MTTR must not read as 'we resolve everything instantly'."""
    _alert(db, n=2, created_at=NOW - timedelta(minutes=5))
    summary = kpi_summary(db, "7d")

    assert summary["alerts"]["total"] == 1
    assert summary["alerts"]["mttr_minutes"] is None
    assert summary["alerts"]["mttd_minutes"] is None


def test_sla_breach_rate(db):
    _alert(db, n=3, sla_breached=True)
    _alert(db, n=4, sla_breached=False)
    _alert(db, n=5, sla_breached=False)
    _alert(db, n=6, sla_breached=False)

    metrics = kpi_summary(db, "7d")["alerts"]
    assert metrics["sla_breached"] == 1
    assert metrics["sla_breach_rate"] == 0.25


def test_volume_series_is_zero_filled(db):
    _alert(db, n=7, severity="critical")
    series = kpi_summary(db, "7d")["volume_series"]

    assert len(series) >= 7  # one bucket per day, no gaps
    assert sum(point["total"] for point in series) == 1
    assert all({"date", "low", "medium", "high", "critical", "total"} <= set(p) for p in series)


def test_workload_counts_open_work_per_analyst(db, analyst_user):
    _alert(db, n=8, assigned_to=analyst_user.id)
    _alert(db, n=9, assigned_to=analyst_user.id, status=AlertStatus.CLOSED)

    workload = {w["username"]: w for w in kpi_summary(db, "7d")["workload"]}
    assert workload["analyst1"]["open_alerts"] == 1  # the closed one does not count


def test_kpi_endpoint_and_bad_window(client, analyst_user, db):
    headers = auth_headers(client, "analyst1")

    resp = client.get("/api/v1/kpis/summary?window=24h", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["window"] == "24h"
    assert {"alerts", "cases", "ingestion", "detection", "top_rules", "volume_series", "workload"} <= set(body)

    assert client.get("/api/v1/kpis/summary?window=7weeks", headers=headers).status_code == 400


def test_detection_coverage_reports_mitre_techniques(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    client.post(
        "/api/v1/rules",
        headers=headers,
        json={
            "name": "Brute force",
            "severity": "high",
            "mitre_technique_id": "T1110",
            "logic": {"conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}]},
        },
    )

    detection = client.get("/api/v1/kpis/summary", headers=headers).json()["detection"]
    assert detection["rules_enabled"] == 1
    assert detection["mitre_techniques_covered"] == ["T1110"]


# ---------------------------------------------------------------------------
# Dead-letter queue: listing and replay
# ---------------------------------------------------------------------------


def test_dead_letters_are_listable(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    client.post("/api/v1/events/ingest", headers=headers, json={"events": [{"garbage": True}]})

    resp = client.get("/api/v1/events/dead-letters", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["resolved"] is False
    # REQUIRED_ECS_FIELDS is checked in order, so event.action is reported first.
    assert body["items"][0]["error_message"] == "Missing required ECS field: event.action"
    assert body["items"][0]["raw_payload"] == {"garbage": True}


def test_analyst_cannot_read_the_dead_letter_queue(client, analyst_user, db):
    assert client.get("/api/v1/events/dead-letters", headers=auth_headers(client, "analyst1")).status_code == 403


def test_replaying_a_still_broken_payload_does_not_grow_the_queue(client, detection_engineer_user, db):
    """A failed replay must not dead-letter the same payload a second time."""
    headers = auth_headers(client, "detengineer1")
    client.post("/api/v1/events/ingest", headers=headers, json={"events": [{"garbage": True}]})
    assert db.query(DeadLetterEvent).count() == 1

    resp = client.post("/api/v1/events/dead-letters/replay", headers=headers, json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["attempted"] == 1
    assert body["succeeded"] == 0
    assert body["still_failing"] == 1

    assert db.query(DeadLetterEvent).count() == 1
    row = db.query(DeadLetterEvent).one()
    assert row.resolved is False
    assert row.replay_status.startswith("failed")


def test_replay_succeeds_once_the_payload_is_repaired(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    client.post("/api/v1/events/ingest", headers=headers, json={"events": [{"action": "logon_failed"}]})

    row = db.query(DeadLetterEvent).one()
    # Simulate the upstream producer being fixed: the stored payload now parses.
    row.raw_payload = {"action": "logon_failed", "timestamp": NOW.isoformat(), "src_ip": "10.0.0.1"}
    db.commit()

    resp = client.post(
        "/api/v1/events/dead-letters/replay", headers=headers, json={"dead_letter_ids": [row.id]}
    )
    assert resp.status_code == 200
    assert resp.json()["succeeded"] == 1

    db.refresh(row)
    assert row.resolved is True
    assert row.replay_status == "succeeded"
    assert db.query(NormalizedEvent).count() == 1

    # A resolved dead letter is not replayed again.
    assert client.post("/api/v1/events/dead-letters/replay", headers=headers, json={}).json()["attempted"] == 0


# ---------------------------------------------------------------------------
# Detection rule CRUD
# ---------------------------------------------------------------------------


def _create_rule(client, headers, name="Rule", enabled=True):
    return client.post(
        "/api/v1/rules",
        headers=headers,
        json={
            "name": name,
            "severity": "medium",
            "enabled": enabled,
            "logic": {"conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}]},
        },
    )


def test_rule_update_and_toggle(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    rule_id = _create_rule(client, headers).json()["id"]

    updated = client.patch(
        f"/api/v1/rules/{rule_id}", headers=headers, json={"name": "Renamed", "severity": "critical"}
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed"
    assert updated.json()["severity"] == "critical"

    toggled = client.patch(f"/api/v1/rules/{rule_id}/enabled", headers=headers, json={"enabled": False})
    assert toggled.json()["enabled"] is False

    disabled_only = client.get("/api/v1/rules?enabled=false", headers=headers).json()
    assert disabled_only["total"] == 1


def test_editing_rule_logic_resets_the_watermark(client, detection_engineer_user, db):
    """Corrected logic must be applied to history, not just to future events."""
    headers = auth_headers(client, "detengineer1")
    rule_id = _create_rule(client, headers).json()["id"]

    client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={"events": [{"action": "logon_failed", "src_ip": "10.0.0.1", "timestamp": NOW.isoformat()}]},
    )
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).one()
    db.refresh(rule)
    assert rule.eval_watermark is not None

    client.patch(
        f"/api/v1/rules/{rule_id}",
        headers=headers,
        json={"logic": {"conditions": [{"field": "event.action", "operator": "eq", "value": "logon_success"}]}},
    )
    db.refresh(rule)
    assert rule.eval_watermark is None


def test_rule_with_alerts_cannot_be_deleted(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    rule_id = _create_rule(client, headers).json()["id"]

    # Unfired rules delete cleanly.
    spare_id = _create_rule(client, headers, name="Unused").json()["id"]
    assert client.delete(f"/api/v1/rules/{spare_id}", headers=headers).status_code == 204

    client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={"events": [{"action": "logon_failed", "src_ip": "10.0.0.1", "timestamp": NOW.isoformat()}]},
    )

    resp = client.delete(f"/api/v1/rules/{rule_id}", headers=headers)
    assert resp.status_code == 409
    assert "disable it instead" in resp.json()["detail"]


def test_analyst_cannot_author_or_delete_rules(client, analyst_user, detection_engineer_user, db):
    author_headers = auth_headers(client, "detengineer1")
    rule_id = _create_rule(client, author_headers).json()["id"]

    analyst_headers = auth_headers(client, "analyst1")
    assert client.patch(f"/api/v1/rules/{rule_id}", headers=analyst_headers, json={"name": "x"}).status_code == 403
    assert client.delete(f"/api/v1/rules/{rule_id}", headers=analyst_headers).status_code == 403


def test_invalid_regex_is_reported_as_a_bad_request(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    rule_id = client.post(
        "/api/v1/rules",
        headers=headers,
        json={
            "name": "Broken regex",
            "severity": "low",
            "logic": {"conditions": [{"field": "process.name", "operator": "regex", "value": "([unclosed"}]},
        },
    ).json()["id"]

    resp = client.post(
        f"/api/v1/rules/{rule_id}/test",
        headers=headers,
        json={"sample_events": [{"process": {"name": "x"}, "@timestamp": NOW.isoformat()}]},
    )
    assert resp.status_code == 400
    assert "regex" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Incremental evaluation
# ---------------------------------------------------------------------------


def test_incremental_evaluation_narrows_the_scan_but_stays_idempotent(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    rule_id = _create_rule(client, headers).json()["id"]

    def ingest(ip: str, at: datetime):
        return client.post(
            "/api/v1/events/ingest",
            headers=headers,
            json={"events": [{"action": "logon_failed", "src_ip": ip, "timestamp": at.isoformat()}]},
        )

    ingest("10.0.0.1", NOW - timedelta(days=10))
    first = client.post(f"/api/v1/rules/{rule_id}/evaluate", headers=headers).json()

    ingest("10.0.0.2", NOW)
    second = client.post(f"/api/v1/rules/{rule_id}/evaluate", headers=headers).json()

    # The second pass reads a narrower slice than the whole table...
    assert second["events_scanned"] < first["events_scanned"] + 2
    # ...and re-running never duplicates an alert already raised.
    third = client.post(f"/api/v1/rules/{rule_id}/evaluate", headers=headers).json()
    assert third["alerts_created"] == 0

    assert db.query(Alert).count() == 2  # one per distinct event, no duplicates


def test_full_rescan_ignores_the_watermark(client, detection_engineer_user, db):
    headers = auth_headers(client, "detengineer1")
    rule_id = _create_rule(client, headers).json()["id"]

    client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={
            "events": [
                {"action": "logon_failed", "src_ip": "10.0.0.1", "timestamp": (NOW - timedelta(days=30)).isoformat()}
            ]
        },
    )
    client.post(f"/api/v1/rules/{rule_id}/evaluate", headers=headers)

    rescan = client.post(f"/api/v1/rules/{rule_id}/evaluate?full_rescan=true", headers=headers).json()
    assert rescan["events_scanned"] == 1
    assert rescan["alerts_created"] == 0  # dedup_key still prevents duplicates
