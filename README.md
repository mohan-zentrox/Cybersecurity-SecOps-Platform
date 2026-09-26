# Project Aegis

**A defensive Security Operations Center (SOC) platform.** Aegis ingests
security event telemetry, enriches it with threat intelligence, runs
detection rules against it, raises and *routes* alerts to on-call
responders, tracks investigations as cases under an enforced SLA, ingests
vulnerability scans, generates compliance evidence, and records every
privileged action in a tamper-evident audit log.

This is **not** an offensive/attack tool and must not be extended into one.
See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for a STRIDE review.

---

## Quick start

```bash
git clone https://github.com/mohan-zentrox/Cybersecurity-SecOps-Platform.git
cd Cybersecurity-SecOps-Platform
cp .env.example .env
docker compose up --build
```

Then open **http://localhost:5173** and sign in as `admin` / `AegisAdmin!2024`.

Compose runs migrations and seeds the database before the API starts, so
the console has working accounts, detection rules, threat indicators,
assets, vulnerabilities and a batch of demo telemetry that has already
raised real alerts. Nothing else to configure.

| Service | URL |
|---------|-----|
| Console | http://localhost:5173 |
| API | http://localhost:8000 |
| Interactive API docs | http://localhost:8000/docs |
| Liveness / readiness | http://localhost:8000/healthz · `/readyz` |

---

## Seeded credentials

Created by `python -m app.seed`, which compose runs automatically.

| Username   | Password              | Role                 | What this role can do |
|------------|-----------------------|----------------------|------------------------|
| `admin`    | `AegisAdmin!2024`     | `admin`              | Everything: users, notification channels, all SOC and compliance functions |
| `analyst`  | `AegisAnalyst!2024`   | `analyst`            | Triage alerts, run and close cases, manage vulnerability remediation, read detection rules |
| `detector` | `AegisDetect!2024`    | `detection-engineer` | Everything an analyst can, plus author detection rules, manage threat intel, import scans, and work the dead-letter queue |
| `auditor`  | `AegisAudit!2024`     | `compliance`         | Read the audit log, verify the hash chain, and generate compliance reports |

> **These are development credentials.** They are printed by the seed
> script and documented here so the platform is usable out of the box.
> Change them (Account → Change password, or Settings → Users) before any
> deployment reachable by anyone else. In production the app also refuses
> to start with a default `JWT_SECRET_KEY`.

Sign in as each role to see different things — the navigation and the
available actions change. Authorization is enforced server-side, so typing
a URL directly still returns 403.

---

## What you can do with it

### 1. Watch the dashboard
`admin` or `analyst` → **Dashboard**. Open alerts, SLA breaches, MTTD,
MTTA, MTTR (mean and p95), alert volume by day and severity, the noisiest
detection rules, per-analyst workload, and pipeline health. The seeded
demo data already populates all of it.

### 2. Triage an alert into a case
**Alerts** → filter by severity or "SLA breached" → tick one or more →
**Promote to case**. Alerts tagged with a red *Threat intel* line matched a
stored indicator. Bulk-triage and bulk-close work from the same toolbar.

### 3. Close a case properly
Open a case → **Close case**. You must record a disposition
(true positive / false positive / benign / duplicate / inconclusive). This
is deliberate: without it "closed" carries no meaning and false-positive
rate — the number that drives rule tuning — cannot be computed. The
timeline is append-only, so the whole investigation stays auditable.

### 4. Write a detection rule
Sign in as `detector` → **Detection** → **New rule**. Build conditions
against ECS fields (`event.action`, `source.ip`, `process.command_line`,
`threat.indicator.matched`, …) with 10 operators, AND/OR matching, and an
optional threshold window like "5 failed logons from one IP in 5 minutes".
Use the built-in **test harness** to run it against sample events without
persisting anything, then **Evaluate now** to run it against real history.

### 5. Feed it events
```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"detector","password":"AegisDetect!2024"}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -X POST localhost:8000/api/v1/events/ingest \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"events":[
        {"action":"logon_failed","src_ip":"203.0.113.66","username":"svc","timestamp":"2026-09-26T10:00:00Z"},
        {"action":"logon_failed","src_ip":"203.0.113.66","username":"svc","timestamp":"2026-09-26T10:00:20Z"}
      ]}'
```
Field names are flexible — `src_ip`, `source_ip` and `source.ip` all
normalize to ECS `source.ip`. Events that cannot be normalized go to the
dead-letter queue rather than being dropped, and can be inspected and
replayed from **Events → Dead letters**.

### 6. Manage threat intelligence
**Threat Intel** → add an indicator, or configure an `http_json` / OTX /
MISP feed and poll it. Indicators are matched against every ingested event
and written onto it as `threat.indicator.*`, so detection rules can match
on them directly. The *Hits* column shows which indicators are actually
earning their place.

### 7. Import a vulnerability scan
As `detector` or `admin` → **Vulnerabilities** → **Import scan**. Accepts
Tenable `.nessus` XML and Qualys-style CSV. Re-importing the same scan
updates findings instead of duplicating them, and a finding that reappears
after being marked remediated is automatically reopened. Select findings
and promote them to a case, exactly like alerts.

### 8. Prove compliance
As `auditor` → **Compliance** → pick a framework and period → **Generate**.
15 controls across SOC 2, ISO 27001 and PCI DSS are evaluated against live
platform data — audit-chain integrity, SLA performance, detection coverage,
vulnerability posture, notification reliability. Download a self-contained
HTML report (print to PDF from any browser). Verdicts are *derived*: tamper
with the audit log and the corresponding control flips to `fail`.

### 9. Verify the audit trail
As `auditor` → **Audit** → **Verify chain**. Each row commits to the hash
of the row before it, so editing, deleting or reordering any historical row
is detectable. Export to CSV with the chain hashes to re-verify offline.

### 10. Route alerts to humans
As `admin` → **Settings → Notifications**. Add a webhook, Slack or SMTP
channel with a minimum-severity floor and **Send test**. Every dispatch
attempt — sent, failed, or skipped for being below the floor — is recorded
under **Deliveries**, so you can prove whether a page actually went out.

---

## Running without Docker

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export DATABASE_URL="sqlite:///./aegis.db"          # or a PostgreSQL URL
export JWT_SECRET_KEY="a-long-random-value-at-least-32-characters"

alembic upgrade head        # create the schema
python -m app.seed          # users, rules, channels, controls, demo data
uvicorn app.main:app --reload
```

Seeding is idempotent — re-running adds only what is missing.
`python -m app.seed --minimal` skips the demo data; `--reset` drops every
table first (destructive).

### Frontend

```bash
cd frontend
npm install
npm run dev     # http://localhost:5173, proxies /api to localhost:8000
```

### Ingestion worker (optional)

By default the ingest request normalizes and detects in-process, which is
deterministic and fine for dev. To make the queue actually absorb load, set
`INGEST_MODE=worker` and `QUEUE_BACKEND=redis`, then run:

```bash
python -m app.worker
```

The worker reads with Redis consumer groups and acknowledges only after a
batch is durably written, so a crash mid-batch replays rather than losing
events.

---

## Tests

```bash
cd backend && pytest                 # 113 tests
cd frontend && npm test              # 21 tests
```

Backend tests run entirely against in-memory SQLite — no Postgres or Redis
required. Coverage is 77%.

Verified on this build:

| Check | Result |
|-------|--------|
| `pytest` | **113 passed** |
| `pytest --cov=app` | **77%** line coverage |
| `ruff check app tests` | clean |
| `bandit -r app -ll` | clean at medium+ severity |
| `npm test` (vitest) | **21 passed** |
| `npm run lint` | clean |
| `npm run build` | builds |
| `alembic upgrade head` / `downgrade base` | applies and reverses cleanly (18 tables) |
| `python -m app.seed` | 4 users, 8 rules, 7 IOCs, 15 controls, 55 events → 6 alerts |

What the tests actually cover: auth and RBAC, user lifecycle (including the
last-admin lockout guard), ingestion and dead-lettering, threat-intel
enrichment (including that lookups stay batched), the rule engine
(operators, AND/OR, threshold bursts, idempotency, incremental evaluation),
the alert/case state machine, required closure dispositions, SLA breach
detection and its once-only guarantee, notification dispatch and failure
handling, outbound URL scheme rejection, scanner parsing and dedup,
compliance evidence collection (including that a tampered audit log flips a
control to `fail`), KPI arithmetic, dead-letter replay, and the hash-chained
audit log under tampering.

---

## Repository layout

```
backend/
  app/
    api/v1/       auth, users, events, rules, alerts, cases, threat_intel,
                  vulnerabilities, compliance, notifications, kpis, audit
    core/         config, security, RBAC deps, rate limiting, pagination, logging
    db/           engine/session wiring, declarative base, portable JSON column
    models/       11 modules, 18 tables
    schemas/      Pydantic request/response models
    services/     normalizer, enrichment, rule_engine, notifications, sla,
                  scheduler, threat_feeds, vuln_ingest, compliance, kpi,
                  queue, audit_chain, state_machine
    seed.py       database seeding
    worker.py     standalone ingestion worker
    main.py       app factory, lifespan, health probes
  alembic/        migrations (0001_initial)
  tests/          9 test modules
frontend/
  src/
    api/          typed clients for every endpoint
    components/   Navbar, ProtectedRoute, Toast, shared UI primitives
    pages/        Dashboard, Alerts, Cases, CaseDetail, Rules, RuleEditor,
                  Events, ThreatIntel, Vulnerabilities, Compliance, Audit,
                  Settings, Account, Login
    store/        auth store and role helpers
    test/         vitest suites
  nginx.conf      SPA fallback + /api proxy for the production image
docs/             ARCHITECTURE, API, THREAT_MODEL, TEAM
.github/          CI: lint, tests, SAST, dependency/image/secret scanning,
                  and a compose smoke test that logs in through the proxy
```

---

## Configuration

Everything is environment-driven (12-factor); see `.env.example` for the
full annotated list. The settings most worth knowing:

| Variable | Default | Notes |
|----------|---------|-------|
| `DATABASE_URL` | local Postgres | SQLite works for dev; refused in production |
| `JWT_SECRET_KEY` | dev placeholder | Must be changed and ≥32 chars in production |
| `CORS_ORIGINS` | localhost dev origins | Must not be `*` in production |
| `INGEST_MODE` | `inline` | `worker` hands ingestion to `app/worker.py` |
| `QUEUE_BACKEND` | `memory` | `redis` for multi-process deployments |
| `SCHEDULER_ENABLED` | `true` | Run in exactly **one** replica when scaling out |
| `SLA_MINUTES_*` | 60 / 240 / 1440 / 4320 | Response deadline per severity |
| `RULE_EVAL_LOOKBACK_SECONDS` | `3600` | Overlap so threshold windows spanning a batch still fire |

With `ENV=production` the app validates its own configuration at startup
and refuses to boot on a default secret, a wildcard CORS origin, or a
SQLite database.

---

## Security posture

- Passwords hashed with bcrypt; login is rate-limited per (username, IP)
  and every attempt is audited.
- RBAC enforced by a FastAPI dependency on each endpoint, not ad-hoc checks
  in handlers. The UI hides what a role cannot use, but that is usability —
  the server is the boundary.
- Audit log is hash-chained and independently verifiable.
- Outbound webhook and feed URLs are restricted to `http`/`https`, so a
  `file://` URL cannot turn a notification into a local file read.
- Scanner XML is parsed with `defusedxml`, a hard dependency with no
  fallback to the vulnerable stdlib parser.
- Containers run as a non-root user; the console ships a strict CSP and the
  standard security headers.
- CI blocks on lint, tests, SAST and secret scanning.

Known limitations are documented honestly in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#known-limitations) — in-process
scheduler and rate limiter, no JWT revocation list, and event search
limited to promoted ECS columns.

---

## Roles referenced in this repo

Application RBAC roles are `analyst`, `detection-engineer`, `compliance`,
`admin`. These are distinct from the team Role IDs (`T5-SEC1`, `T5-BE1`,
`T5-DEV1`, `T5-FE1`, `T5-DATA1`, `T5-QA1`) documented in
[`docs/TEAM.md`](docs/TEAM.md).
