# Project Aegis — Architecture

Project Aegis is **defensive, internal SOC tooling**: it ingests security
event telemetry, enriches it with threat intelligence, evaluates detection
rules against it, raises and routes alerts, tracks investigations as cases
under an enforced SLA, ingests vulnerability scans, generates compliance
evidence, and keeps a tamper-evident audit trail of privileged actions. It
is not, and must not be extended into, an offensive/attack tool.

## Stack

| Layer         | Technology                                                                 |
|---------------|----------------------------------------------------------------------------|
| Frontend      | React 18 + TypeScript + Tailwind CSS (Vite), Vitest                        |
| Backend       | FastAPI (Python 3.12) + Pydantic v2 + SQLAlchemy 2.0                       |
| Relational DB | PostgreSQL (rules, alerts, cases, assets, IOCs, users, audit)              |
| Event store   | Repository-pattern abstraction; Postgres/JSONB today, OpenSearch swap-in documented |
| Buffering     | Queue abstraction; in-process or Redis Streams (consumer groups) today, Kafka adapter documented |
| Schema        | ECS (Elastic Common Schema)-aligned normalization                          |
| Auth          | JWT bearer session tokens + RBAC via FastAPI dependency, rate-limited login |
| Migrations    | Alembic (`0001_initial` creates all 18 tables)                             |
| Observability | Structured JSON logging with per-request correlation ids                   |
| CI/CD         | Docker + GitHub Actions (lint, tests, SAST, dependency + image + secret scanning, compose smoke test) |

## Request flow: ingestion → enrichment → detection → alerting → case

```
raw event (JSON, arbitrary field names)
   │
   ▼
POST /api/v1/events/ingest  (app/api/v1/events.py)
   │  enqueues onto the Queue abstraction (app/services/queue.py)
   │
   ├─ INGEST_MODE=inline  → drained in-request (deterministic; dev/tests)
   └─ INGEST_MODE=worker  → drained by app/worker.py (load-absorbing)
   │
   ▼
normalizer (app/services/normalizer.py)
   │  maps aliases -> ECS fields (event.action, source.ip, user.name, ...)
   │  on failure -> dead_letter_events table (inspectable + replayable)
   ▼
threat-intel enrichment (app/services/enrichment.py)
   │  batched IOC lookup; writes threat.indicator.* onto the ECS document
   ▼
event store (PostgresJSONBEventStore implements EventStoreRepository)
   │
   ▼
rule engine (app/services/rule_engine.py)
   │  incremental: reads events newer than (watermark - lookback)
   │  conditions + optional threshold/window; idempotent via Alert.dedup_key
   │  stamps first_event_at and a severity-driven sla_due_at
   ▼
Alert (new) ──PATCH status──> investigating ──> closed | escalated
   │                          (stamps acknowledged_at / closed_at)
   │
   ├─ notification dispatch (app/services/notifications.py)
   │     log | webhook | Slack | SMTP, filtered by channel min_severity,
   │     every attempt recorded as a NotificationDelivery
   │
   │ POST /api/v1/alerts/promote
   ▼
Case (immutable CaseTimelineEvent log, SLA timer, required closure disposition)
   ▲
   └── POST /api/v1/vulnerabilities/promote (same workflow for CVEs)

   scheduler (app/services/scheduler.py), every SLA_SWEEP_INTERVAL_SECONDS:
      sweep_sla_breaches() → flags overdue alerts/cases, audits, notifies
```

Every privileged action along this path (login, user changes, rule
mutation, alert/case status change, comment, assignment, promotion, IOC
authorship, scan import, report generation) is appended to the
hash-chained `audit_events` table (`app/services/audit_chain.py`). See
`GET /api/v1/audit/verify` to check chain integrity at any time.

## Repository-pattern abstractions (why they exist)

Two seams are deliberately abstracted behind an interface so a component
can be swapped without touching callers, per FRD-ING-03/04:

1. **Event store** — `EventStoreRepository` (app/services/normalizer.py).
   `PostgresJSONBEventStore` is the implementation used today; a future
   `OpenSearchEventStore` would implement the same `write_event` /
   `query_events` / `count_events` methods for search-at-scale.
2. **Queue** — `Queue` (app/services/queue.py). `InMemoryQueue` (tests,
   single-process dev) and `RedisStreamQueue` (docker-compose) are
   implemented; `KafkaQueueAdapter` is a documented extension point.

A third seam exists for threat intel: `ThreatIntelFeedClient`
(app/services/threat_feeds.py) has `manual`, `http_json`, `otx` and `misp`
implementations, so adding a feed type is a new class rather than an edit
to the polling loop.

## Design decisions worth knowing

**At-least-once ingestion.** `RedisStreamQueue` uses consumer groups
(`XREADGROUP` + `XACK`), not `XRANGE` + `XDEL`. Messages are acknowledged
only after the normalizer has durably written them, and entries orphaned
by a crashed worker are reclaimed with `XAUTOCLAIM`. A delete-before-
process design would be at-most-once and would silently lose events on a
mid-batch crash.

**Incremental rule evaluation.** Re-reading every stored event for every
enabled rule on every ingest is O(rules × all events). Each rule carries an
`eval_watermark`; a run reads only events newer than
`watermark - RULE_EVAL_LOOKBACK_SECONDS`. The deliberate overlap lets a
threshold window that straddles a batch boundary still fire, and
`dedup_key` makes the overlap safe. Editing a rule's logic resets the
watermark so corrected logic is applied to history, not just to the future.

**Closure requires a disposition.** A case cannot move to `closed` without
a `resolution`. Without it, "closed" carries no analytical meaning and
false-positive rate — the number that drives rule tuning — is not
computable.

**Lifecycle timestamps over log reconstruction.** `first_event_at`,
`acknowledged_at` and `closed_at` are stamped on the row as transitions
happen, so MTTD/MTTA/MTTR are simple aggregates rather than a replay of the
audit log.

**Outbound URL scheme validation.** `urlopen` also speaks `file:`, `ftp:`
and `data:`. Notification and feed URLs are checked against an http/https
allowlist before the request is made, so a channel configured with
`file:///etc/passwd` cannot turn an alert dispatch into a local file read.

**defusedxml is a hard dependency.** Scanner uploads are attacker-influenced
XML. There is deliberately no fallback to the stdlib parser, because a
fallback means an install without defusedxml silently gets the vulnerable
one.

**Notifications never fail the pipeline.** Dispatch is best-effort and
records failures on the delivery row. A dead Slack webhook must not stop an
alert being recorded.

**Compliance evidence is derived, not asserted.** Each control binds to a
collector function that queries live platform data. Tamper with the audit
log and the corresponding control flips to `fail` on the next report — this
is covered by a test.

## Fully implemented

- **Auth & users** — rate-limited, audited login; JWT session tokens;
  role-gated dependency; full user lifecycle (create, role change, soft
  delete, admin reset, self-service password change) with a last-admin
  lockout guard.
- **Ingestion** — batch ingest, queue buffering, ECS normalization,
  dead-lettering with inspection and replay, searchable event index.
- **Threat intel** — IOC inventory with bulk import, four feed client
  types, scheduled polling, batched enrichment writing `threat.indicator.*`
  onto events so rules can match on it.
- **Detection** — full rule CRUD, 10 operators, AND/OR, threshold-over-
  window bursts with grouping, persistence-free test harness, incremental
  evaluator, MITRE technique tagging.
- **Alerting** — notification channels (log/webhook/Slack/SMTP) with
  severity floors and a delivery audit trail; bulk triage; assignment.
- **Cases** — immutable timeline, SLA timers, enforced closure disposition,
  comments, assignment, promotion from alerts *or* vulnerabilities.
- **SLA enforcement** — background sweep flags overdue work exactly once,
  audits it, and notifies.
- **Vulnerability management** — Nessus XML and CSV parsers, asset
  inventory, dedup on re-import, reopen-on-reappearance, remediation
  tracking, promotion to case.
- **Compliance** — 15 controls across SOC2 / ISO27001 / PCI-DSS bound to 7
  evidence collectors; immutable generated reports with a self-contained
  HTML artifact.
- **KPIs** — MTTD, MTTA, MTTR (mean and p95), SLA breach rate, alert volume
  series, noisiest rules, analyst workload, pipeline health.
- **Audit** — hash-chained log, verification endpoint, filtering, CSV
  export including chain hashes for offline re-verification.

## Known limitations

- The scheduler runs in-process. Scaling the API horizontally requires
  `SCHEDULER_ENABLED=false` on all but one replica, or a distributed lock.
- The login rate limiter is in-process, so it is per-replica rather than
  global. Swap in a Redis counter behind the same `RateLimiter` interface
  for a multi-replica deployment.
- JWTs are stateless: logout is client-side only, and there is no
  revocation list or refresh-token rotation. Token lifetime is the control.
- Compliance report generation is synchronous. It is fast (aggregate
  queries over local tables), and the report row already models an async
  lifecycle, so moving it onto the queue changes only the route body.
- The event store search filters on promoted ECS columns, not on arbitrary
  paths inside the JSON document. Arbitrary-field search is what the
  documented OpenSearch swap-in is for.
