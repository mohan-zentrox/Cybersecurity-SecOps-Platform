# Project Aegis — Threat Model (STRIDE, brief)

Scope: this platform is internal/defensive SOC tooling. It ingests
security telemetry, evaluates detection rules, and manages the resulting
investigations. This document is a starting point (owner: T5-SEC1), not a
complete assessment — extend it as new components (threat-intel,
vuln-scan ingestion, compliance reporting) move out of scaffold status.

## Auth (`app/api/v1/auth.py`, `core/security.py`, `core/deps.py`)

| STRIDE | Risk | Mitigation in this repo |
|---|---|---|
| Spoofing | Credential stuffing / brute force | Per-username+IP sliding-window rate limiter (`core/rate_limit.py`), failed logins audited |
| Tampering | Forged session token | JWT signed with `JWT_SECRET_KEY` (HS256); rotate this secret via env var, never commit it |
| Repudiation | "I didn't do that" after a privileged action | Every login attempt and privileged mutation is written to the hash-chained audit log |
| Information Disclosure | Password exposure | Passwords hashed with bcrypt (never stored/logged in plaintext); generic 401 on bad username *or* password (no user enumeration) |
| Elevation of Privilege | Role escalation via a compromised low-priv account | Role is embedded in the signed JWT and re-checked server-side on every request via `require_roles()`, not trusted from client state |

## Ingestion (`api/v1/events.py`, `services/normalizer.py`, `services/queue.py`)

| STRIDE | Risk | Mitigation / residual risk |
|---|---|---|
| Tampering | Malicious/malformed raw events (injection via field values) | Values are stored as data (JSON columns / parameterized ORM queries), never interpolated into SQL or shell; malformed events are dead-lettered, not silently coerced |
| Denial of Service | Ingest flooding | Queue abstraction absorbs bursts; **residual risk**: no per-source rate limit yet on `/events/ingest` itself — recommended follow-up |
| Information Disclosure | Sensitive data (PII, secrets) inside raw event payloads | Raw payload is retained for forensics (`NormalizedEvent.raw`); **residual risk**: no field-level redaction yet — flag for compliance review before ingesting production-sensitive sources |

## Detection & Alerting (`services/rule_engine.py`, `api/v1/rules.py`, `api/v1/alerts.py`)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Rule logic manipulated to suppress detections | Rule creation restricted to `detection-engineer`/`admin`; rule mutations are audited |
| Repudiation | Alert status silently changed | State machine transitions are audited with `from`/`to`, and the transition itself is rejected (400) if invalid |
| Elevation of Privilege | Any role running `POST /rules/{id}/evaluate` on arbitrary rules | Restricted to analyst/detection-engineer/admin; compliance role deliberately excluded (read-only over audit, not an operational role) |

## Case Management (`api/v1/cases.py`)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Editing case history after the fact | `CaseTimelineEvent` rows are append-only — no update/delete endpoint exists for them |
| Repudiation | Disputed SLA compliance | `sla_due_at` fixed at case creation from severity; timeline records every status change with actor + timestamp |

## Audit log (`services/audit_chain.py`)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Attacker with DB access edits/deletes historical rows | Hash chain (`prev_hash` + `content_hash`) makes any in-place edit or deletion detectable via `GET /audit/verify`; **residual risk**: this detects tampering, it does not prevent DB-level access — production deployments should also apply DB-level write restrictions/backups |
| Elevation of Privilege | Non-compliance roles reading the audit trail | `GET /audit*` restricted to `compliance`/`admin` |

## Transport / Deployment

| STRIDE | Risk | Mitigation / residual risk |
|---|---|---|
| Information Disclosure | Traffic sniffing | TLS termination is expected at the ingress/reverse proxy in front of `docker-compose.yml` — not configured in this foundation repo (local dev only) |
| Tampering | Supply-chain (dependency) compromise | CI runs `pip-audit` / `bandit` (see `.github/workflows/ci.yml`) as a first line of defense |
