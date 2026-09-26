# Project Aegis — API reference

Base path: `/api/v1`. Interactive docs: `http://localhost:8000/docs`.

All endpoints except `POST /auth/login` and the health probes require an
`Authorization: Bearer <token>` header. Roles are `analyst`,
`detection-engineer`, `compliance`, `admin`.

Every collection endpoint returns a page envelope:

```json
{ "items": [...], "total": 128, "limit": 50, "offset": 0 }
```

and accepts `?limit=` (1–500) and `?offset=`.

---

## Health

| Method | Path       | Auth | Notes |
|--------|------------|------|-------|
| GET    | `/healthz` | none | Liveness. Never touches dependencies. |
| GET    | `/readyz`  | none | Readiness. Checks DB and Redis; returns **503** when degraded. |

## Auth

| Method | Path           | Role | Notes |
|--------|----------------|------|-------|
| POST   | `/auth/login`  | none | Rate-limited per (username, IP). Returns a JWT. |
| GET    | `/auth/me`     | any  | The signed-in user. |

```bash
curl -X POST localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"AegisAdmin!2024"}'
```

## Users

| Method | Path                          | Role  |
|--------|-------------------------------|-------|
| GET    | `/users`                      | any   |
| POST   | `/users`                      | admin |
| GET    | `/users/{id}`                 | any   |
| PATCH  | `/users/{id}`                 | admin |
| DELETE | `/users/{id}`                 | admin (soft delete) |
| POST   | `/users/{id}/password-reset`  | admin |
| POST   | `/users/me/password`          | any (requires current password) |

Filters: `role`, `is_active`. Deactivating the last active admin, or your
own account, is refused with 400.

## Events

| Method | Path                             | Role | Notes |
|--------|----------------------------------|------|-------|
| POST   | `/events/ingest`                 | any  | Batch of up to 10,000 raw events. |
| GET    | `/events`                        | any  | Search the normalized store. |
| GET    | `/events/{id}`                   | any  | Full ECS document + raw payload. |
| GET    | `/events/dead-letters`           | detection-engineer, admin |
| POST   | `/events/dead-letters/replay`    | detection-engineer, admin |

Search filters: `event_action`, `event_category`, `source_ip`,
`destination_ip`, `user_name`, `host_name`, `threat_matched`, `since`,
`until`.

```bash
curl -X POST localhost:8000/api/v1/events/ingest -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "events": [
      {"action":"logon_failed","src_ip":"203.0.113.66","username":"svc",
       "timestamp":"2026-09-26T10:00:00Z"}
    ]
  }'
```

Response reports `accepted`, `dead_lettered`, `threat_matches`,
`stored_event_ids` and `alerts_created`.

## Detection rules

| Method | Path                          | Role |
|--------|-------------------------------|------|
| GET    | `/rules`                      | any  |
| POST   | `/rules`                      | detection-engineer, admin |
| GET    | `/rules/{id}`                 | any  |
| PATCH  | `/rules/{id}`                 | detection-engineer, admin |
| PATCH  | `/rules/{id}/enabled`         | detection-engineer, admin |
| DELETE | `/rules/{id}`                 | detection-engineer, admin (409 if alerts reference it) |
| POST   | `/rules/{id}/test`            | analyst+ (never persists) |
| POST   | `/rules/{id}/evaluate`        | analyst+ (`?full_rescan=true` ignores the watermark) |

Rule logic:

```json
{
  "match": "all",
  "conditions": [
    {"field": "event.action", "operator": "eq", "value": "logon_failed"}
  ],
  "threshold": {"count": 5, "window_seconds": 300, "group_by": "source.ip"}
}
```

Operators: `eq`, `neq`, `contains`, `regex`, `in`, `gt`, `gte`, `lt`,
`lte`, `exists`. Omit `threshold` to alert on every matching event.

## Alerts

| Method | Path                       | Role |
|--------|----------------------------|------|
| GET    | `/alerts`                  | any  |
| GET    | `/alerts/{id}`             | any  |
| PATCH  | `/alerts/{id}/status`      | analyst+ |
| PATCH  | `/alerts/{id}/assign`      | analyst+ |
| POST   | `/alerts/bulk/status`      | analyst+ (up to 500) |
| POST   | `/alerts/promote`          | analyst+ → creates a Case |

Filters: `status`, `severity`, `assigned_to`, `unassigned`, `rule_id`,
`sla_breached`, `search`.

Transitions: `new → investigating → (closed | escalated)`; `escalated →
(investigating | closed)`; `closed` is terminal. Anything else is 400.

## Cases

| Method | Path                       | Role |
|--------|----------------------------|------|
| GET    | `/cases`                   | any  |
| GET    | `/cases/{id}`              | any (includes timeline) |
| PATCH  | `/cases/{id}/status`       | analyst+ |
| POST   | `/cases/{id}/comments`     | analyst+ |
| PATCH  | `/cases/{id}/assign`       | analyst+ |

Closing requires a disposition, or the request is rejected with 422:

```json
{"status": "closed", "resolution": "true_positive",
 "resolution_summary": "Confirmed credential stuffing; account disabled."}
```

Resolutions: `true_positive`, `false_positive`, `benign_true_positive`,
`duplicate`, `inconclusive`.

## Threat intelligence

| Method | Path                                  | Role |
|--------|---------------------------------------|------|
| GET    | `/threat-intel/iocs`                  | any  |
| POST   | `/threat-intel/iocs`                  | detection-engineer, admin |
| POST   | `/threat-intel/iocs/bulk`             | detection-engineer, admin (up to 10,000) |
| PATCH  | `/threat-intel/iocs/{id}`             | detection-engineer, admin |
| DELETE | `/threat-intel/iocs/{id}`             | detection-engineer, admin (deactivates) |
| GET    | `/threat-intel/feeds`                 | any  |
| POST   | `/threat-intel/feeds`                 | detection-engineer, admin |
| POST   | `/threat-intel/feeds/{id}/poll`       | detection-engineer, admin |

IOC types: `ip`, `domain`, `url`, `file_hash`, `email`. Feed kinds:
`manual`, `http_json`, `otx`, `misp`.

## Vulnerabilities

| Method | Path                                    | Role |
|--------|-----------------------------------------|------|
| POST   | `/vulnerabilities/ingest`               | detection-engineer, admin (multipart, ≤50 MiB) |
| GET    | `/vulnerabilities`                      | any  |
| GET    | `/vulnerabilities/{id}`                 | any  |
| PATCH  | `/vulnerabilities/{id}/status`          | analyst+ |
| POST   | `/vulnerabilities/promote`              | analyst+ → creates a Case |
| GET    | `/vulnerabilities/assets`               | any  |
| POST   | `/vulnerabilities/assets`               | detection-engineer, admin |
| PATCH  | `/vulnerabilities/assets/{id}`          | detection-engineer, admin |
| GET    | `/vulnerabilities/imports`              | any  |

```bash
curl -X POST localhost:8000/api/v1/vulnerabilities/ingest \
  -H "Authorization: Bearer $TOKEN" -F 'file=@scan.nessus'
```

Formats: Tenable `.nessus` XML, Qualys-style CSV. Auto-detected, or force
with `?scanner=nessus|csv`.

## Compliance

| Method | Path                                    | Role |
|--------|-----------------------------------------|------|
| GET    | `/compliance/frameworks`                | compliance, admin |
| GET    | `/compliance/controls`                  | compliance, admin |
| POST   | `/compliance/controls/seed`             | admin |
| GET    | `/compliance/reports`                   | compliance, admin |
| POST   | `/compliance/reports`                   | compliance, admin |
| GET    | `/compliance/reports/{id}`              | compliance, admin |
| GET    | `/compliance/reports/{id}/download`     | compliance, admin (HTML) |

Frameworks: `SOC2`, `ISO27001`, `PCI-DSS`. Reporting period is capped at
400 days.

## Notifications

| Method | Path                                     | Role |
|--------|------------------------------------------|------|
| GET    | `/notifications/channels`                | any  |
| POST   | `/notifications/channels`                | admin |
| PATCH  | `/notifications/channels/{id}`           | admin |
| DELETE | `/notifications/channels/{id}`           | admin |
| POST   | `/notifications/channels/{id}/test`      | admin |
| GET    | `/notifications/deliveries`              | any  |

Channel types: `log`, `webhook`, `slack`, `email`. Webhook and Slack
channels require `config.url`, and only `http`/`https` schemes are accepted.

## KPIs

| Method | Path                  | Role |
|--------|-----------------------|------|
| GET    | `/kpis/summary`       | any (`?window=24h|7d|30d`) |
| POST   | `/kpis/sla-sweep`     | analyst, admin |

Returns MTTD/MTTA/MTTR (mean and p95), SLA breach rates, alert volume
series, noisiest rules, analyst workload, ingestion health and detection
coverage.

## Audit

| Method | Path              | Role |
|--------|-------------------|------|
| GET    | `/audit`          | compliance, admin |
| GET    | `/audit/verify`   | compliance, admin |
| GET    | `/audit/actions`  | compliance, admin |
| GET    | `/audit/export`   | compliance, admin (CSV with chain hashes) |

`/audit/verify` walks the chain and reports the first row where either the
stored `prev_hash` breaks the link or the recomputed content hash differs.

## Error shapes

| Status | Meaning |
|--------|---------|
| 400 | Invalid state transition, bad window spec, business-rule violation |
| 401 | Missing/invalid/expired token, or inactive user |
| 403 | Authenticated but the role is not permitted |
| 404 | Resource not found |
| 409 | Conflict (duplicate username, rule still referenced by alerts) |
| 413 | Upload exceeds the size limit |
| 422 | Schema validation failed (FastAPI's per-field `detail` list) |
| 429 | Login rate limit exceeded |
| 503 | `/readyz` only: a dependency is unreachable |

Every response carries an `X-Request-ID` header matching the `request.id`
field in the structured logs.
