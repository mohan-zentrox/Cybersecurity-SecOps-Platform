"""
User lifecycle management (FRD-AUTH-05): creation, RBAC on the management
endpoints, role changes, soft deletion, and password handling.
"""

from app.core.security import verify_password
from app.models.user import AppRole, User
from tests.conftest import DEFAULT_PASSWORD, auth_headers, make_user

NEW_USER = {
    "username": "newanalyst",
    "email": "newanalyst@example.com",
    "password": "An0ther-Str0ng-Pw!",
    "role": "analyst",
}


def test_admin_can_create_user_and_the_user_can_log_in(client, admin_user, db):
    headers = auth_headers(client, "admin1")

    resp = client.post("/api/v1/users", headers=headers, json=NEW_USER)
    assert resp.status_code == 201, resp.text
    assert resp.json()["username"] == "newanalyst"
    assert "password" not in resp.text and "hashed_password" not in resp.text

    # The created account is immediately usable — the whole point of the endpoint.
    login = client.post(
        "/api/v1/auth/login", json={"username": "newanalyst", "password": NEW_USER["password"]}
    )
    assert login.status_code == 200
    assert login.json()["role"] == "analyst"


def test_non_admin_cannot_create_users(client, analyst_user, db):
    resp = client.post("/api/v1/users", headers=auth_headers(client, "analyst1"), json=NEW_USER)
    assert resp.status_code == 403


def test_duplicate_username_or_email_is_rejected(client, admin_user, db):
    headers = auth_headers(client, "admin1")
    assert client.post("/api/v1/users", headers=headers, json=NEW_USER).status_code == 201

    assert client.post("/api/v1/users", headers=headers, json=NEW_USER).status_code == 409

    same_email = {**NEW_USER, "username": "different"}
    assert client.post("/api/v1/users", headers=headers, json=same_email).status_code == 409


def test_weak_password_is_rejected_before_hashing(client, admin_user, db):
    resp = client.post(
        "/api/v1/users", headers=auth_headers(client, "admin1"), json={**NEW_USER, "password": "short"}
    )
    assert resp.status_code == 422


def test_role_change_takes_effect_on_the_next_token(client, admin_user, db):
    target = make_user(db, username="promoteme", role=AppRole.ANALYST)
    admin_headers = auth_headers(client, "admin1")

    # As an analyst, rule authoring is refused.
    analyst_headers = auth_headers(client, "promoteme")
    rule_payload = {
        "name": "test rule",
        "severity": "low",
        "logic": {"conditions": [{"field": "event.action", "operator": "eq", "value": "x"}]},
    }
    assert client.post("/api/v1/rules", headers=analyst_headers, json=rule_payload).status_code == 403

    resp = client.patch(
        f"/api/v1/users/{target.id}", headers=admin_headers, json={"role": "detection-engineer"}
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "detection-engineer"

    upgraded_headers = auth_headers(client, "promoteme")
    assert client.post("/api/v1/rules", headers=upgraded_headers, json=rule_payload).status_code == 201


def test_deactivated_user_cannot_authenticate(client, admin_user, db):
    target = make_user(db, username="leaver", role=AppRole.ANALYST)
    headers = auth_headers(client, "admin1")

    assert client.delete(f"/api/v1/users/{target.id}", headers=headers).status_code == 200

    login = client.post(
        "/api/v1/auth/login", json={"username": "leaver", "password": DEFAULT_PASSWORD}
    )
    assert login.status_code == 401


def test_cannot_deactivate_the_last_active_admin(client, admin_user, db):
    """A lockout guard: removing the final administrator would leave the
    platform with no one able to manage it."""
    other = make_user(db, username="admin2", role=AppRole.ADMIN)
    headers = auth_headers(client, "admin1")

    # Removing one of two admins is allowed.
    assert client.delete(f"/api/v1/users/{other.id}", headers=headers).status_code == 200

    # Removing the last one is not — even via the update endpoint.
    resp = client.patch(f"/api/v1/users/{admin_user.id}", headers=headers, json={"is_active": False})
    assert resp.status_code == 400
    assert "last active administrator" in resp.json()["detail"]


def test_admin_cannot_deactivate_self(client, admin_user, db):
    headers = auth_headers(client, "admin1")
    resp = client.delete(f"/api/v1/users/{admin_user.id}", headers=headers)
    assert resp.status_code == 400


def test_self_service_password_change(client, analyst_user, db):
    headers = auth_headers(client, "analyst1")
    new_password = "Rotated-Passw0rd!"

    wrong = client.post(
        "/api/v1/users/me/password",
        headers=headers,
        json={"current_password": "not-the-password", "new_password": new_password},
    )
    assert wrong.status_code == 400

    resp = client.post(
        "/api/v1/users/me/password",
        headers=headers,
        json={"current_password": DEFAULT_PASSWORD, "new_password": new_password},
    )
    assert resp.status_code == 200

    db.expire_all()
    refreshed = db.query(User).filter(User.username == "analyst1").one()
    assert verify_password(new_password, refreshed.hashed_password)
    assert not verify_password(DEFAULT_PASSWORD, refreshed.hashed_password)

    assert (
        client.post("/api/v1/auth/login", json={"username": "analyst1", "password": new_password}).status_code
        == 200
    )


def test_admin_password_reset_does_not_need_the_old_password(client, admin_user, db):
    target = make_user(db, username="forgot", role=AppRole.ANALYST)
    resp = client.post(
        f"/api/v1/users/{target.id}/password-reset",
        headers=auth_headers(client, "admin1"),
        json={"new_password": "Admin-Set-Passw0rd!"},
    )
    assert resp.status_code == 200
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "forgot", "password": "Admin-Set-Passw0rd!"}
        ).status_code
        == 200
    )


def test_user_list_is_paginated_and_filterable(client, admin_user, db):
    for i in range(5):
        make_user(db, username=f"bulk{i}", role=AppRole.ANALYST)
    headers = auth_headers(client, "admin1")

    resp = client.get("/api/v1/users?limit=2", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 2
    assert body["total"] == 6  # 5 created + the admin
    assert body["limit"] == 2

    filtered = client.get("/api/v1/users?role=analyst", headers=headers).json()
    assert filtered["total"] == 5
    assert all(u["role"] == "analyst" for u in filtered["items"])


def test_user_management_is_audited(client, admin_user, db):
    headers = auth_headers(client, "admin1")
    client.post("/api/v1/users", headers=headers, json=NEW_USER)

    audit = client.get("/api/v1/audit?action=user_created", headers=headers).json()
    assert audit["total"] == 1
    assert audit["items"][0]["details"]["username"] == "newanalyst"
