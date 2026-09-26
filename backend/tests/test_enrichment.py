"""
Threat-intel enrichment (FRD-TI-01/03): indicator upsert, batched lookup,
ECS annotation, and the fact that enriched events are then matchable by
detection rules via `threat.indicator.*`.
"""

from datetime import datetime, timedelta, timezone

from app.models.event import NormalizedEvent
from app.models.ioc import IOC, IOCType
from app.services.enrichment import enrich_events, extract_candidates, upsert_ioc
from app.services.normalizer import process_raw_batch
from tests.conftest import auth_headers


def _event(**overrides) -> dict:
    base = {
        "action": "logon_success",
        "category": "authentication",
        "src_ip": "203.0.113.66",
        "username": "svc",
        "hostname": "web-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    base.update(overrides)
    return base


def test_upsert_is_idempotent_and_normalizes_the_lookup_key(db):
    first, created_first = upsert_ioc(db, ioc_type=IOCType.IP, value="  203.0.113.66  ", confidence=60)
    assert created_first is True
    assert first.value_normalized == "203.0.113.66"

    # Same indicator, different spacing/case -> updates rather than duplicating.
    second, created_second = upsert_ioc(db, ioc_type=IOCType.IP, value="203.0.113.66", confidence=90)
    assert created_second is False
    assert second.id == first.id
    assert second.confidence == 90  # confidence takes the maximum
    assert db.query(IOC).count() == 1


def test_extract_candidates_reads_every_configured_ecs_path():
    candidates = extract_candidates(
        {
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "203.0.113.5"},
            "dns": {"question": {"name": "Evil.Example"}},
            "file": {"hash": {"sha256": "ABC123"}},
        }
    )
    assert candidates[IOCType.IP] == {"10.0.0.1", "203.0.113.5"}
    assert candidates[IOCType.DOMAIN] == {"evil.example"}  # lower-cased
    assert candidates[IOCType.FILE_HASH] == {"abc123"}


def test_matching_event_is_annotated_and_counted(db):
    upsert_ioc(db, ioc_type=IOCType.IP, value="203.0.113.66", confidence=90, severity="critical")
    process_raw_batch(db, [_event()])

    event = db.query(NormalizedEvent).one()
    assert event.threat_matched is True

    indicator = event.ecs["threat"]["indicator"]
    assert indicator["matched"] is True
    assert indicator["max_confidence"] == 90
    assert indicator["indicators"][0]["value"] == "203.0.113.66"

    # The hit counter on the indicator is maintained.
    assert db.query(IOC).one().match_count == 1


def test_non_matching_event_is_left_alone(db):
    upsert_ioc(db, ioc_type=IOCType.IP, value="203.0.113.66")
    process_raw_batch(db, [_event(src_ip="10.0.0.99")])

    event = db.query(NormalizedEvent).one()
    assert event.threat_matched is False
    assert event.enrichment == {}
    assert "threat" not in event.ecs


def test_inactive_and_expired_indicators_do_not_match(db):
    stale, _ = upsert_ioc(db, ioc_type=IOCType.IP, value="203.0.113.66")
    stale.active = False
    expired, _ = upsert_ioc(db, ioc_type=IOCType.IP, value="198.51.100.23")
    expired.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    process_raw_batch(db, [_event(), _event(src_ip="198.51.100.23")])
    assert all(e.threat_matched is False for e in db.query(NormalizedEvent).all())


def test_enrichment_uses_one_query_per_type_not_one_per_event(db):
    """The batching claim in services/enrichment.py, asserted rather than assumed."""
    upsert_ioc(db, ioc_type=IOCType.IP, value="203.0.113.66")

    rows = []
    for i in range(25):
        row = NormalizedEvent(
            event_action="logon_success",
            source_ip="203.0.113.66",
            event_timestamp=datetime.now(timezone.utc),
            ecs={"source": {"ip": "203.0.113.66"}},
            raw={},
        )
        db.add(row)
        rows.append(row)
    db.commit()

    statements: list[str] = []
    from sqlalchemy import event as sa_event

    def _record(conn, cursor, statement, params, context, executemany):
        if "FROM iocs" in statement:
            statements.append(statement)

    sa_event.listen(db.get_bind(), "before_cursor_execute", _record)
    try:
        result = enrich_events(db, rows)
    finally:
        sa_event.remove(db.get_bind(), "before_cursor_execute", _record)

    assert result.events_matched == 25
    # Five IOC types are probed at most; nowhere near one query per event.
    assert len(statements) <= 5


def test_rule_can_match_on_enriched_threat_fields(client, detection_engineer_user, db):
    """End-to-end: indicator -> enrichment -> rule condition -> alert."""
    upsert_ioc(db, ioc_type=IOCType.IP, value="203.0.113.66", confidence=95, severity="critical")
    headers = auth_headers(client, "detengineer1")

    created = client.post(
        "/api/v1/rules",
        headers=headers,
        json={
            "name": "Logon from known-bad IP",
            "severity": "critical",
            "logic": {
                "match": "all",
                "conditions": [
                    {"field": "event.action", "operator": "eq", "value": "logon_success"},
                    {"field": "threat.indicator.matched", "operator": "eq", "value": True},
                ],
            },
        },
    )
    assert created.status_code == 201, created.text

    ingest = client.post("/api/v1/events/ingest", headers=headers, json={"events": [_event()]})
    assert ingest.status_code == 200, ingest.text
    body = ingest.json()
    assert body["accepted"] == 1
    assert body["threat_matches"] == 1
    assert len(body["alerts_created"]) == 1

    alert = client.get(f"/api/v1/alerts/{body['alerts_created'][0]}", headers=headers).json()
    assert alert["severity"] == "critical"
    # The indicator that caused the match is carried on the alert for triage.
    assert alert["enrichment"]["indicators"][0]["value"] == "203.0.113.66"
