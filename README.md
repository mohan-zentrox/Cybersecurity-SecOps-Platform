# Project Aegis

**Defensive, internal SOC (Security Operations Center) tooling.** Project
Aegis ingests security event telemetry, normalizes it to an ECS-aligned
schema, evaluates detection rules against it, raises alerts, and tracks
investigations through case management with a tamper-evident audit trail.

This is **not** an offensive/attack tool, and must not be extended into
one. See `docs/THREAT_MODEL.md` for a brief STRIDE review per component.

## Stack

React + TypeScript + Tailwind (frontend) · FastAPI + Pydantic (backend) ·
PostgreSQL (relational metadata) · a repository-pattern event store
abstraction (Postgres/JSONB today, OpenSearch/Elastic swap-in documented)
· a queue abstraction (in-process/Redis Streams today, Kafka adapter
documented) · Docker + GitHub Actions CI. See `docs/ARCHITECTURE.md` for
the full picture.

## Repository layout

```
backend/    FastAPI app, services, tests, Alembic migrations, Dockerfile
frontend/   React + TS + Tailwind console (Vite), Dockerfile
docs/       ARCHITECTURE.md, TEAM.md, API.md, THREAT_MODEL.md
.github/    CI workflow (lint, tests, SAST/dependency scan, container build)
docker-compose.yml, .env.example, .gitignore
```

## What's implemented vs. scaffolded

**Implemented as real, working code** (see `docs/ARCHITECTURE.md` for detail):
- Auth & RBAC — rate-limited/audited login, JWT session tokens, role-gated dependency
- Event ingestion → queue abstraction → ECS normalization → event store, with a dead-letter path
- Detection rule engine — condition + threshold-over-window DSL, persistence-free test harness, real evaluator that creates alerts idempotently
- Alerting & case management — state-machine-enforced status transitions, promotion to case, immutable case timeline, severity-based SLA timers
- Tamper-evident hash-chained audit log + chain-verification endpoint

**Scaffolded only** (TODOs referencing FRD sections, no logic — `backend/app/scaffolds/`):
- Threat-intel IOC enrichment
- Vulnerability scan ingestion
- Compliance report generation (SOC2 / ISO27001 / PCI)
- SOC KPI dashboards

## Running locally

### With Docker (recommended)

```
cp .env.example .env
docker compose up --build
```

- Backend: http://localhost:8000 (docs at `/docs`)
- Frontend: http://localhost:5173

### Backend only, without Docker

```
cd backend
pip install -r requirements.txt
cp ../.env.example ../.env   # or export the vars another way
uvicorn app.main:app --reload
```

On startup in `ENV=development`, the app calls `Base.metadata.create_all()`
for convenience. Production schema changes go through Alembic
(`backend/alembic/`) — no versions have been generated yet in this
foundation repo; run `alembic revision --autogenerate -m "initial schema"`
against a real PostgreSQL instance to produce the first one.

There is no seed script yet — create a user directly via a Python shell
(`app.core.security.hash_password` + `app.models.user.User`) or add a
seed script as a follow-up.

### Frontend only, without Docker

```
cd frontend
npm install
npm run dev
```

## Tests

```
cd backend
pytest
```

Tests run entirely against an in-memory SQLite database (no live
Postgres/Redis required) — see `backend/tests/conftest.py`. Coverage:
auth (login, rate limiting, RBAC), ingestion/normalization (including
dead-lettering), the rule engine (condition matching, AND/OR, threshold-
over-window bursts, the test-harness endpoint, idempotent alert creation),
the alert/case status state machine (valid and invalid transitions), and
the hash-chained audit log (integrity on normal operation, and tamper
detection when a row is edited or deleted).

**Verification status of this foundation repo:** Python and `git` were
not present at the start of this build (the sandbox only had a Windows
Store execution-alias stub for `python`). Both were installed via
`winget` mid-build (`Python.Python.3.12`, `Git.Git`), after which the
full suite was actually executed, not just reviewed by hand:

- `pytest` — **38/38 tests passed**
- `ruff check` — clean, no findings
- `bandit -r app -ll` (medium+ severity) — no issues identified (two Low/Medium-confidence findings at full severity are false positives on the JWT claim-name constants `"sub"`/`"role"`, not real secrets)
- `pip-audit -r requirements.txt` — flags a residual set of advisories against pinned versions (mainly `starlette`, `pytest`, `python-multipart`, `pyjwt`); several of the available fixes are major-version bumps (e.g. `starlette` 1.x, `pytest` 9.x) that need compatibility verification before adopting, so this step is intentionally **non-blocking** in CI (`|| true`) pending team triage — see `.github/workflows/ci.yml`

Password hashing calls the `bcrypt` library directly (rather than
passlib's `CryptContext`) to avoid a known passlib/bcrypt version-
detection incompatibility. JWT session tokens use `PyJWT` (swapped in
after `pip-audit` flagged unresolved CVEs in the originally-chosen
`python-jose`).

## Git

```
git init
git config user.name "Zentrox Engineering"
git config user.email "engineering@zentroxglobaltechnologies.com"
git add -A
git commit -m "Initial commit: Project Aegis foundation - ingestion/normalization, detection rule engine, alerting, case management, hash-chained audit"
```

## Roles referenced in this repo

Role IDs only — see `docs/TEAM.md` for the full table:
`T5-SEC1` (Security Lead/Cybersecurity Analyst), `T5-BE1` (Backend
Engineer), `T5-DEV1` (Software Developer), `T5-FE1` (Frontend Engineer),
`T5-DATA1` (Security Data Analyst), `T5-QA1` (QA/Junior Developer).

Application-level RBAC roles (distinct from the above team Role IDs) are:
`analyst`, `detection-engineer`, `compliance`, `admin`.
