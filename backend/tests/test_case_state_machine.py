"""
Alerting & case management (FRD-ALERT-01..03, FRD-CASE-01..05): promotion
of alerts into a case, immutable timeline, SLA computation, and the
new -> investigating -> (closed | escalated) state machine enforced on
both Alert.status and Case.status.
"""

from app.models.alert import Alert
from app.services.state_machine import InvalidTransitionError, validate_transition
from tests.conftest import auth_headers


def _make_alert(db, *, severity="high", dedup_key="dedup-1") -> Alert:
    alert = Alert(title="Suspicious login burst", severity=severity, status="new", dedup_key=dedup_key)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


# ---------------------------------------------------------------------------
# Pure state machine unit tests
# ---------------------------------------------------------------------------


def test_valid_transition_chain():
    validate_transition("new", "investigating")
    validate_transition("investigating", "escalated")
    validate_transition("escalated", "investigating")
    validate_transition("investigating", "closed")


def test_invalid_transition_raises():
    import pytest

    with pytest.raises(InvalidTransitionError):
        validate_transition("new", "closed")
    with pytest.raises(InvalidTransitionError):
        validate_transition("closed", "investigating")
    with pytest.raises(InvalidTransitionError):
        validate_transition("new", "escalated")


# ---------------------------------------------------------------------------
# Alert status transitions via the API
# ---------------------------------------------------------------------------


def test_alert_valid_status_transition(client, analyst_user, db):
    alert = _make_alert(db)
    headers = auth_headers(client, "analyst1")

    resp = client.patch(f"/api/v1/alerts/{alert.id}/status", headers=headers, json={"status": "investigating"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


def test_alert_invalid_status_transition_rejected(client, analyst_user, db):
    alert = _make_alert(db)
    headers = auth_headers(client, "analyst1")

    resp = client.patch(f"/api/v1/alerts/{alert.id}/status", headers=headers, json={"status": "closed"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Case promotion, timeline, SLA, and status transitions via the API
# ---------------------------------------------------------------------------


def test_promote_alert_to_case_creates_timeline_and_sla(client, analyst_user, db):
    alert = _make_alert(db, severity="critical")
    headers = auth_headers(client, "analyst1")

    resp = client.post("/api/v1/alerts/promote", headers=headers, json={"alert_ids": [alert.id]})
    assert resp.status_code == 201
    case = resp.json()
    assert case["severity"] == "critical"
    assert case["status"] == "new"
    assert case["sla_due_at"] > case["created_at"]

    detail = client.get(f"/api/v1/cases/{case['id']}", headers=headers).json()
    assert detail["alert_ids"] == [alert.id]
    timeline_types = [e["type"] for e in detail["timeline"]]
    assert "created" in timeline_types
    assert "alert_linked" in timeline_types


def test_case_valid_transition_and_timeline_entry(client, analyst_user, db):
    alert = _make_alert(db)
    headers = auth_headers(client, "analyst1")
    case_id = client.post("/api/v1/alerts/promote", headers=headers, json={"alert_ids": [alert.id]}).json()["id"]

    resp = client.patch(f"/api/v1/cases/{case_id}/status", headers=headers, json={"status": "investigating"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "investigating"
    status_changes = [e for e in body["timeline"] if e["type"] == "status_change"]
    assert len(status_changes) == 1
    assert status_changes[0]["content"] == {"from": "new", "to": "investigating"}


def test_case_invalid_transition_rejected_with_400(client, analyst_user, db):
    alert = _make_alert(db)
    headers = auth_headers(client, "analyst1")
    case_id = client.post("/api/v1/alerts/promote", headers=headers, json={"alert_ids": [alert.id]}).json()["id"]

    # new -> closed is not a legal direct transition.
    resp = client.patch(f"/api/v1/cases/{case_id}/status", headers=headers, json={"status": "closed"})
    assert resp.status_code == 400

    # Case status must remain unchanged after the rejected transition.
    detail = client.get(f"/api/v1/cases/{case_id}", headers=headers).json()
    assert detail["status"] == "new"


def test_case_comment_and_assignment_are_recorded_on_timeline(client, analyst_user, db, admin_user):
    alert = _make_alert(db)
    headers = auth_headers(client, "analyst1")
    case_id = client.post("/api/v1/alerts/promote", headers=headers, json={"alert_ids": [alert.id]}).json()["id"]

    client.post(f"/api/v1/cases/{case_id}/comments", headers=headers, json={"comment": "Confirmed malicious"})
    resp = client.patch(f"/api/v1/cases/{case_id}/assign", headers=headers, json={"assigned_to": admin_user.id})
    assert resp.status_code == 200

    detail = resp.json()
    types = [e["type"] for e in detail["timeline"]]
    assert "comment" in types
    assert "assignment" in types
    assert detail["assigned_to"] == admin_user.id
