"""
Ingestion & ECS normalization (FRD-ING-01/02/03): batch ingest via the
API, alias-based field mapping onto ECS paths, and dead-lettering of
malformed events.
"""

from app.models.event import DeadLetterEvent, NormalizedEvent
from tests.conftest import auth_headers


def test_ingest_normalizes_heterogeneous_field_names(client, analyst_user, db):
    headers = auth_headers(client, "analyst1")
    resp = client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={
            "events": [
                {
                    "action": "logon_failed",
                    "src_ip": "10.0.0.5",
                    "username": "jdoe",
                    "hostname": "workstation-1",
                    "timestamp": "2026-07-13T10:00:00Z",
                }
            ]
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] == 1
    assert body["dead_lettered"] == 0

    stored = db.query(NormalizedEvent).all()
    assert len(stored) == 1
    event = stored[0]
    assert event.event_action == "logon_failed"
    assert event.source_ip == "10.0.0.5"
    assert event.user_name == "jdoe"
    assert event.host_name == "workstation-1"
    assert event.ecs["event"]["action"] == "logon_failed"
    assert event.ecs["source"]["ip"] == "10.0.0.5"


def test_ingest_dead_letters_events_missing_required_fields(client, analyst_user, db):
    headers = auth_headers(client, "analyst1")
    resp = client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={"events": [{"src_ip": "10.0.0.5"}]},  # no action, no timestamp
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] == 0
    assert body["dead_lettered"] == 1

    dead = db.query(DeadLetterEvent).all()
    assert len(dead) == 1
    assert "timestamp" in dead[0].error_message.lower() or "action" in dead[0].error_message.lower()


def test_ingest_dead_letters_unparsable_timestamp(client, analyst_user, db):
    headers = auth_headers(client, "analyst1")
    resp = client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={"events": [{"action": "logon_failed", "timestamp": "not-a-timestamp"}]},
    )
    body = resp.json()
    assert body["accepted"] == 0
    assert body["dead_lettered"] == 1
    assert db.query(DeadLetterEvent).count() == 1


def test_ingest_mixed_batch_partial_success(client, analyst_user, db):
    headers = auth_headers(client, "analyst1")
    resp = client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={
            "events": [
                {"action": "logon_success", "timestamp": "2026-07-13T10:00:00Z", "user": "alice"},
                {"src_ip": "1.2.3.4"},  # invalid: missing action/timestamp
            ]
        },
    )
    body = resp.json()
    assert body["accepted"] == 1
    assert body["dead_lettered"] == 1
    assert db.query(NormalizedEvent).count() == 1
    assert db.query(DeadLetterEvent).count() == 1


def test_ingest_requires_authentication(client):
    resp = client.post("/api/v1/events/ingest", json={"events": [{"action": "x", "timestamp": "2026-01-01T00:00:00Z"}]})
    assert resp.status_code == 401
