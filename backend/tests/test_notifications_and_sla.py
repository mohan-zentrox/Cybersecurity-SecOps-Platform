"""
Alert notification delivery (FRD-ALERT-04) and SLA breach detection
(FRD-ALERT-05 / FRD-CASE-05).

These two together are what turn "a row was written to the alerts table"
into "somebody was actually told, and we noticed when nobody acted".
"""

from datetime import datetime, timedelta, timezone

from app.models.alert import Alert, AlertStatus
from app.models.audit import AuditEvent
from app.models.case import Case, CaseStatus, CaseTimelineEvent, TimelineEventType
from app.models.notification import ChannelType, DeliveryStatus, NotificationChannel, NotificationDelivery
from app.services.notifications import Notification, dispatch, severity_meets
from app.services.rule_engine import sla_due_for
from app.services.sla import sweep_sla_breaches
from tests.conftest import auth_headers


def _log_channel(db, *, name="log-sink", min_severity="low", enabled=True) -> NotificationChannel:
    channel = NotificationChannel(
        name=name, type=ChannelType.LOG, min_severity=min_severity, enabled=enabled, config={}
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return channel


def _notification(severity="high") -> Notification:
    return Notification(
        subject_type="test", subject_id=1, severity=severity, title="Test alert", body="body"
    )


def _alert(db, *, severity="high", status=AlertStatus.NEW, sla_due_at=None, dedup="d1") -> Alert:
    alert = Alert(
        title="Test alert",
        severity=severity,
        status=status,
        dedup_key=dedup,
        sla_due_at=sla_due_at,
        matched_event_ids=[],
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


# ---------------------------------------------------------------------------
# Notification dispatch
# ---------------------------------------------------------------------------


def test_severity_floor_comparison():
    assert severity_meets("critical", "high") is True
    assert severity_meets("high", "high") is True
    assert severity_meets("medium", "high") is False


def test_dispatch_records_a_delivery_per_channel(db):
    _log_channel(db, name="a")
    _log_channel(db, name="b")

    deliveries = dispatch(db, _notification())

    assert len(deliveries) == 2
    assert {d.status for d in deliveries} == {DeliveryStatus.SENT}
    assert db.query(NotificationDelivery).count() == 2


def test_dispatch_skips_channels_below_their_severity_floor(db):
    _log_channel(db, name="critical-only", min_severity="critical")

    deliveries = dispatch(db, _notification(severity="medium"))

    assert len(deliveries) == 1
    assert deliveries[0].status == DeliveryStatus.SKIPPED
    assert "min_severity" in deliveries[0].detail


def test_dispatch_ignores_disabled_channels(db):
    _log_channel(db, name="off", enabled=False)
    assert dispatch(db, _notification()) == []


def test_dispatch_records_failure_without_raising(db):
    """A dead Slack webhook must not stop an alert being recorded."""
    db.add(
        NotificationChannel(
            name="broken-webhook",
            type=ChannelType.WEBHOOK,
            min_severity="low",
            enabled=True,
            config={},  # no url -> the transport raises
        )
    )
    db.commit()

    deliveries = dispatch(db, _notification())

    assert len(deliveries) == 1
    assert deliveries[0].status == DeliveryStatus.FAILED
    assert "url" in deliveries[0].detail


def test_raising_an_alert_dispatches_a_notification(client, detection_engineer_user, db):
    _log_channel(db)
    headers = auth_headers(client, "detengineer1")
    client.post(
        "/api/v1/rules",
        headers=headers,
        json={
            "name": "Any failed logon",
            "severity": "high",
            "logic": {"conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}]},
        },
    )

    resp = client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={
            "events": [
                {"action": "logon_failed", "src_ip": "10.0.0.1", "timestamp": datetime.now(timezone.utc).isoformat()}
            ]
        },
    )
    assert len(resp.json()["alerts_created"]) == 1

    delivery = db.query(NotificationDelivery).filter(NotificationDelivery.subject_type == "alert").one()
    assert delivery.status == DeliveryStatus.SENT
    assert delivery.subject_id == resp.json()["alerts_created"][0]


def test_channel_test_send_is_recorded(client, admin_user, db):
    channel = _log_channel(db)
    resp = client.post(
        f"/api/v1/notifications/channels/{channel.id}/test", headers=auth_headers(client, "admin1")
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "sent"
    assert db.query(NotificationDelivery).filter(NotificationDelivery.subject_type == "test").count() == 1


def test_only_admins_manage_channels(client, analyst_user, db):
    resp = client.post(
        "/api/v1/notifications/channels",
        headers=auth_headers(client, "analyst1"),
        json={"name": "x", "type": "log"},
    )
    assert resp.status_code == 403


def test_webhook_channel_requires_a_url(client, admin_user, db):
    resp = client.post(
        "/api/v1/notifications/channels",
        headers=auth_headers(client, "admin1"),
        json={"name": "hook", "type": "webhook", "config": {}},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# SLA breach detection
# ---------------------------------------------------------------------------


def test_sla_due_date_follows_severity():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert sla_due_for("critical", now) == now + timedelta(minutes=60)
    assert sla_due_for("high", now) == now + timedelta(minutes=240)
    assert sla_due_for("low", now) == now + timedelta(minutes=4320)


def test_overdue_alert_is_flagged_audited_and_notified(db):
    _log_channel(db)
    overdue = _alert(db, sla_due_at=datetime.now(timezone.utc) - timedelta(minutes=5))

    result = sweep_sla_breaches(db)

    assert result.alerts_breached == [overdue.id]
    db.refresh(overdue)
    assert overdue.sla_breached is True

    assert db.query(AuditEvent).filter(AuditEvent.action == "alert_sla_breached").count() == 1
    assert (
        db.query(NotificationDelivery).filter(NotificationDelivery.subject_type == "sla_breach").count() == 1
    )


def test_alert_within_sla_is_not_flagged(db):
    _alert(db, sla_due_at=datetime.now(timezone.utc) + timedelta(hours=1))
    assert sweep_sla_breaches(db).total == 0


def test_closed_alert_is_never_breached(db):
    _alert(db, status=AlertStatus.CLOSED, sla_due_at=datetime.now(timezone.utc) - timedelta(hours=1))
    assert sweep_sla_breaches(db).total == 0


def test_breach_is_recorded_once_across_repeated_sweeps(db):
    """The sweep runs on a timer; it must not re-page every minute forever."""
    _log_channel(db)
    _alert(db, sla_due_at=datetime.now(timezone.utc) - timedelta(minutes=5))

    assert sweep_sla_breaches(db).total == 1
    assert sweep_sla_breaches(db).total == 0
    assert sweep_sla_breaches(db).total == 0

    assert db.query(AuditEvent).filter(AuditEvent.action == "alert_sla_breached").count() == 1


def test_overdue_case_gets_a_timeline_entry(db):
    case = Case(
        title="Overdue investigation",
        severity="high",
        status=CaseStatus.INVESTIGATING,
        sla_due_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    result = sweep_sla_breaches(db)

    assert result.cases_breached == [case.id]
    entries = (
        db.query(CaseTimelineEvent)
        .filter(CaseTimelineEvent.case_id == case.id, CaseTimelineEvent.type == TimelineEventType.SLA_BREACH)
        .all()
    )
    assert len(entries) == 1
    assert entries[0].actor == "system"


def test_sla_sweep_endpoint(client, admin_user, db):
    _alert(db, sla_due_at=datetime.now(timezone.utc) - timedelta(minutes=5))
    resp = client.post("/api/v1/kpis/sla-sweep", headers=auth_headers(client, "admin1"))
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


# ---------------------------------------------------------------------------
# Outbound URL safety
# ---------------------------------------------------------------------------


def test_non_http_webhook_urls_are_refused(db):
    """urlopen also speaks file:/ftp:/data:. A channel pointed at
    file:///etc/passwd must not turn an alert dispatch into a local file read."""
    import pytest

    from app.services.notifications import require_http_url

    for good in ("http://hooks.example.com/x", "https://hooks.example.com/x"):
        assert require_http_url(good, what="webhook URL") == good

    for bad in ("file:///etc/passwd", "ftp://example.com/x", "data:text/plain,hi", "/just/a/path"):
        with pytest.raises(ValueError):
            require_http_url(bad, what="webhook URL")


def test_dispatch_to_a_file_url_channel_fails_safely(db):
    """The guard surfaces as a recorded delivery failure, not an exception
    escaping into the detection pipeline."""
    db.add(
        NotificationChannel(
            name="file-exfil",
            type=ChannelType.WEBHOOK,
            min_severity="low",
            enabled=True,
            config={"url": "file:///etc/passwd"},
        )
    )
    db.commit()

    deliveries = dispatch(db, _notification())

    assert len(deliveries) == 1
    assert deliveries[0].status == DeliveryStatus.FAILED
    assert "http(s)" in deliveries[0].detail
