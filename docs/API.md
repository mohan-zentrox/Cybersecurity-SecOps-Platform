# Project Aegis — API Reference (v1)

Base path: `/api/v1`. All endpoints except `/auth/login` and `/healthz`
require `Authorization: Bearer <token>`, obtained from `/auth/login`.
Roles: `analyst`, `detection-engineer`, `compliance`, `admin`.

## Auth

| Method | Path          | Role     | Notes                                                        |
|--------|---------------|----------|---------------------------------------------------------------|
| POST   | `/auth/login` | none     | Rate-limited (5 attempts / 60s per username+IP), audited     |
| GET    | `/auth/me`    | any      | Returns the authenticated user                                |

`POST /auth/login` body: `{"username": "...", "password": "..."}` →
`{"access_token", "token_type", "username", "role"}`.

## Events

| Method | Path                  | Role | Notes                                                                 |
|--------|------------------------|------|-------------------------------------------------------------------------|
| POST   | `/events/ingest`       | any  | Body: `{"events": [ {...raw event...}, ... ]}`. Normalizes to ECS, stores, dead-letters failures, auto-runs enabled detection rules. |

Response: `{"accepted", "dead_lettered", "stored_event_ids", "alerts_created"}`.

Accepted raw field aliases (see `app/services/normalizer.py`): `action`/`event_action` → `event.action`; `src_ip`/`source_ip` → `source.ip`; `user`/`username` → `user.name`; `hostname`/`host` → `host.name`; `timestamp`/`time` → `@timestamp`, etc.

## Detection rules

| Method | Path                         | Role                          | Notes                                             |
|--------|-------------------------------|--------------------------------|----------------------------------------------------|
| POST   | `/rules`                      | detection-engineer, admin      | Create a rule                                     |
| GET    | `/rules`                      | any                             | List rules                                        |
| GET    | `/rules/{id}`                 | any                             | Get a rule                                        |
| POST   | `/rules/{id}/test`            | analyst, detection-engineer, admin | Run against `sample_events`; **never persists alerts** |
| POST   | `/rules/{id}/evaluate`        | analyst, detection-engineer, admin | Run against the stored event store; creates alerts (idempotent) |

Rule `logic` shape:
```json
{
  "match": "all",
  "conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}],
  "threshold": {"count": 5, "window_seconds": 300, "group_by": "source.ip"}
}
```
Operators: `eq, neq, contains, gt, gte, lt, lte, in`.

## Alerts

| Method | Path                     | Role                          | Notes                                  |
|--------|---------------------------|--------------------------------|------------------------------------------|
| GET    | `/alerts`                 | any                             | List alerts                             |
| GET    | `/alerts/{id}`             | any                             | Get one alert                           |
| PATCH  | `/alerts/{id}/status`      | analyst, detection-engineer, admin | State machine enforced; invalid transitions → 400 |
| PATCH  | `/alerts/{id}/assign`      | analyst, detection-engineer, admin | Body: `{"assigned_to": <user_id>}`      |
| POST   | `/alerts/promote`          | analyst, detection-engineer, admin | Body: `{"alert_ids": [...], "title"?}` → creates a Case |

## Cases

| Method | Path                       | Role                          | Notes                                     |
|--------|------------------------------|--------------------------------|----------------------------------------------|
| GET    | `/cases`                     | any                             | List cases                                  |
| GET    | `/cases/{id}`                 | any                             | Case detail with full immutable timeline    |
| PATCH  | `/cases/{id}/status`          | analyst, detection-engineer, admin | State machine enforced; invalid → 400        |
| POST   | `/cases/{id}/comments`        | analyst, detection-engineer, admin | Body: `{"comment": "..."}`                   |
| PATCH  | `/cases/{id}/assign`          | analyst, detection-engineer, admin | Body: `{"assigned_to": <user_id>}`           |

Status state machine (shared by Alert and Case): `new → investigating → (closed | escalated)`, `escalated ↔ investigating`, `escalated → closed`. `closed` is terminal.

## Audit

| Method | Path             | Role                  | Notes                                            |
|--------|-------------------|------------------------|----------------------------------------------------|
| GET    | `/audit`           | compliance, admin      | List all audit events                              |
| GET    | `/audit/verify`    | compliance, admin      | Walks the hash chain; returns `{"intact", "total_events", "first_broken_event_id", "reason"}` |

## Health

| Method | Path       | Role | Notes                     |
|--------|------------|------|-----------------------------|
| GET    | `/healthz` | none | Liveness check (not under `/api/v1`) |
