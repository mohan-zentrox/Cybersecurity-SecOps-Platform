# Project Aegis — Architecture

Project Aegis is **defensive, internal SOC tooling**: it ingests security
event telemetry, evaluates detection rules against it, raises alerts,
tracks investigations as cases, and keeps a tamper-evident audit trail of
privileged actions. It is not, and must not be extended into, an
offensive/attack tool.

## Stack

| Layer        | Technology                                                        |
|--------------|---------------------------------------------------------------------|
| Frontend     | React + TypeScript + Tailwind CSS (Vite)                          |
| Backend      | FastAPI (Python) + Pydantic v2                                     |
| Relational DB| PostgreSQL (rules, alerts, cases, assets, users, audit)            |
| Event store  | Repository-pattern abstraction; Postgres/JSONB today, OpenSearch/Elastic swap-in documented (not implemented) |
| Buffering    | Queue abstraction; in-process/Redis Streams today, Kafka adapter documented (not implemented) |
| Schema       | ECS (Elastic Common Schema)-aligned normalization                  |
| Auth         | Session-based login (JWT bearer token) + RBAC via FastAPI dependency, rate-limited |
| CI/CD        | Docker + GitHub Actions (lint, tests, container build, SAST/dependency scan) |

## Request flow: ingestion → detection → alerting → case management

```
raw event (JSON, arbitrary field names)
   │
   ▼
POST /api/v1/events/ingest  (app/api/v1/events.py)
   │  enqueues onto Queue abstraction (app/services/queue.py)
   ▼
normalizer (app/services/normalizer.py)
   │  maps aliases -> ECS fields (event.action, source.ip, user.name, ...)
   │  on failure -> dead_letter_events table
   ▼
event store (PostgresJSONBEventStore, implements EventStoreRepository)
   │
   ▼
rule engine (app/services/rule_engine.py)
   │  evaluates enabled DetectionRules (condition + optional threshold/window)
   │  idempotent via Alert.dedup_key
   ▼
Alert (new) ──PATCH status──> investigating ──> closed | escalated
   │
   │ POST /api/v1/alerts/promote
   ▼
Case (immutable CaseTimelineEvent log, SLA timer by severity)
```

Every privileged action along this path (login, rule mutation, alert/case
status change, comment, assignment, promotion) is appended to the
hash-chained `audit_events` table (`app/services/audit_chain.py`). See
`GET /api/v1/audit/verify` to check chain integrity at any time.

## Repository-pattern abstractions (why they exist)

Two seams are deliberately abstracted behind an interface so a component
can be swapped without touching callers, per FRD-ING-03/04:

1. **Event store** — `EventStoreRepository` (app/services/normalizer.py).
   `PostgresJSONBEventStore` is the implementation used today; a future
   `OpenSearchEventStore` would implement the same `write_event` /
   `query_events` methods for search-at-scale.
2. **Queue** — `Queue` (app/services/queue.py). `InMemoryQueue` (tests,
   single-process dev) and `RedisStreamQueue` (docker-compose) are
   implemented; `KafkaQueueAdapter` is a documented extension point.

## Implemented vs. scaffolded

**Implemented (real, tested logic):**
- Auth: rate-limited, audited login; JWT session tokens; role-gated dependency (`app/core/deps.py`).
- Ingestion & ECS normalization, with dead-letter handling.
- Detection rule engine: field/operator/value conditions, AND/OR, threshold-over-window bursts, test harness endpoint, real evaluator that creates alerts idempotently.
- Alerting: state-machine-enforced status transitions, assignment, promotion to Case.
- Case management: immutable timeline, SLA due-date computation, status/comment/assignment endpoints.
- Tamper-evident hash-chained audit log + verification endpoint.

**Scaffolded only (TODOs referencing FRD sections, no logic — see `backend/app/scaffolds/`):**
- Threat-intel IOC enrichment (`threat_intel.py`)
- Vulnerability scan ingestion (`vuln_scan_ingestion.py`)
- Compliance report generation — SOC2/ISO27001/PCI (`compliance_reports.py`)
- SOC KPI dashboards (`soc_kpi_dashboards.py`)

## Database migrations

Schema changes are managed via Alembic (`backend/alembic/`). No versions
have been generated yet in this foundation repo — run
`alembic revision --autogenerate -m "initial schema"` against a real
PostgreSQL instance to produce the first migration. Tests do not depend on
Alembic; they create the schema directly against an in-memory SQLite
engine for speed and isolation (see `backend/tests/conftest.py`).
