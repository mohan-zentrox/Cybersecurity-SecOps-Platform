"""
Tamper-evident hash-chained audit log (FRD-AUDIT-01/02): chain integrity
on normal operation, and detection of in-place row tampering.
"""

from app.models.audit import GENESIS_HASH, AuditEvent
from app.services.audit_chain import append_audit_event, verify_chain
from tests.conftest import auth_headers


def test_first_event_chains_to_genesis(db):
    row = append_audit_event(db, actor="system", action="test_action", resource="test:1", details={})
    assert row.prev_hash == GENESIS_HASH
    assert row.content_hash != GENESIS_HASH


def test_chain_is_intact_after_normal_appends(db):
    for i in range(5):
        append_audit_event(db, actor="system", action=f"action_{i}", resource=f"res:{i}", details={"i": i})

    result = verify_chain(db)
    assert result.intact is True
    assert result.total_events == 5
    assert result.first_broken_event_id is None


def test_each_row_prev_hash_equals_previous_content_hash(db):
    first = append_audit_event(db, actor="system", action="a", resource="r1", details={})
    second = append_audit_event(db, actor="system", action="b", resource="r2", details={})
    assert second.prev_hash == first.content_hash


def test_verify_detects_content_tampering(db):
    append_audit_event(db, actor="system", action="a", resource="r1", details={"amount": 1})
    target = append_audit_event(db, actor="system", action="b", resource="r2", details={"amount": 2})
    append_audit_event(db, actor="system", action="c", resource="r3", details={"amount": 3})

    # Tamper with a historical row's content directly (bypassing the append API,
    # simulating an attacker/DBA editing a row in place) without recomputing hashes.
    row = db.query(AuditEvent).filter(AuditEvent.id == target.id).one()
    row.details = {"amount": 9999}
    db.commit()

    result = verify_chain(db)
    assert result.intact is False
    assert result.first_broken_event_id == target.id
    assert "content_hash mismatch" in result.reason


def test_verify_detects_deleted_row_breaking_the_chain(db):
    append_audit_event(db, actor="system", action="a", resource="r1", details={})
    second = append_audit_event(db, actor="system", action="b", resource="r2", details={})
    third = append_audit_event(db, actor="system", action="c", resource="r3", details={})

    # Delete a middle row: the next row's prev_hash now points to a hash that no
    # longer has a matching predecessor in the walked sequence.
    db.query(AuditEvent).filter(AuditEvent.id == second.id).delete()
    db.commit()

    result = verify_chain(db)
    assert result.intact is False
    assert result.first_broken_event_id == third.id


def test_verify_endpoint_reports_intact_chain(client, compliance_user, db):
    headers = auth_headers(client, "compliance1")
    # The login itself appends an audit row (login_success), and the compliance
    # role check requires an authenticated call, so the chain already has >=1 row.
    resp = client.get("/api/v1/audit/verify", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["intact"] is True
    assert body["total_events"] >= 1


def test_verify_endpoint_reports_tampering(client, compliance_user, db):
    headers = auth_headers(client, "compliance1")
    row = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    row.action = "tampered_action"
    db.commit()

    resp = client.get("/api/v1/audit/verify", headers=headers)
    body = resp.json()
    assert body["intact"] is False
    assert body["first_broken_event_id"] == row.id


def test_audit_endpoints_require_compliance_or_admin_role(client, analyst_user):
    headers = auth_headers(client, "analyst1")
    resp = client.get("/api/v1/audit", headers=headers)
    assert resp.status_code == 403
    resp = client.get("/api/v1/audit/verify", headers=headers)
    assert resp.status_code == 403
