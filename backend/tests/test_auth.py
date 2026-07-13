"""
Auth & RBAC: login, session token issuance, rate limiting, and audit
logging of login attempts (FRD-AUTH-01/02/04).
"""

from app.core.config import get_settings
from app.models.audit import AuditEvent
from tests.conftest import DEFAULT_PASSWORD, auth_headers


def test_login_success_returns_token(client, analyst_user):
    resp = client.post(
        "/api/v1/auth/login", json={"username": "analyst1", "password": DEFAULT_PASSWORD}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "analyst1"
    assert body["role"] == "analyst"
    assert body["access_token"]


def test_login_wrong_password_is_rejected_and_audited(client, analyst_user, db):
    resp = client.post("/api/v1/auth/login", json={"username": "analyst1", "password": "wrong"})
    assert resp.status_code == 401

    failed_events = db.query(AuditEvent).filter(AuditEvent.action == "login_failed").all()
    assert len(failed_events) == 1
    assert failed_events[0].actor == "analyst1"


def test_login_unknown_user_is_rejected(client):
    resp = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "whatever"})
    assert resp.status_code == 401


def test_login_is_rate_limited_after_repeated_failures(client, analyst_user):
    settings = get_settings()
    for _ in range(settings.LOGIN_RATE_LIMIT_ATTEMPTS):
        resp = client.post("/api/v1/auth/login", json={"username": "analyst1", "password": "wrong"})
        assert resp.status_code == 401

    # One more attempt beyond the configured budget must be throttled, not
    # evaluated against the password at all.
    resp = client.post("/api/v1/auth/login", json={"username": "analyst1", "password": "wrong"})
    assert resp.status_code == 429


def test_protected_endpoint_requires_token(client):
    resp = client.get("/api/v1/rules")
    assert resp.status_code == 401


def test_protected_endpoint_rejects_garbage_token(client):
    resp = client.get("/api/v1/rules", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_me_returns_current_user(client, analyst_user):
    headers = auth_headers(client, "analyst1")
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["username"] == "analyst1"
    assert resp.json()["role"] == "analyst"


def test_role_gating_blocks_wrong_role(client, analyst_user):
    """Only detection-engineer/admin may author rules; analyst must be rejected with 403."""
    headers = auth_headers(client, "analyst1")
    resp = client.post(
        "/api/v1/rules",
        headers=headers,
        json={
            "name": "test rule",
            "severity": "low",
            "logic": {"conditions": [{"field": "event.action", "operator": "eq", "value": "x"}]},
        },
    )
    assert resp.status_code == 403
