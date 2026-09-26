# Project Aegis — Team & Role Assignments

Per the source BRD/FRD/SRS, engineers are referenced **only** by their
Role ID. Do not substitute real names in code, comments, commits, or
documentation.

| Role ID   | Function                              | Primary responsibility on Project Aegis                                   |
|-----------|----------------------------------------|-----------------------------------------------------------------------------|
| T5-SEC1   | Security Lead / Cybersecurity Analyst  | Detection rule design, MITRE ATT&CK mapping, threat model review          |
| T5-BE1    | Backend Engineer                       | FastAPI services, event store abstraction, rule engine, RBAC              |
| T5-DEV1   | Software Developer                     | Case management workflows, state machine, general backend feature work   |
| T5-FE1    | Frontend Engineer                      | React/TypeScript/Tailwind console (Alert Queue, Case Detail, Rules pages) |
| T5-DATA1  | Security Data Analyst                  | ECS field mapping, normalization coverage, SOC KPI definitions            |
| T5-QA1    | QA / Junior Developer                  | pytest coverage, CI pipeline maintenance, regression testing              |

## Ownership map (by repo area)

| Area                                                        | Owner(s)          |
|--------------------------------------------------------------|--------------------|
| `backend/app/core/`, `api/v1/auth.py`, `api/v1/users.py`     | T5-BE1             |
| `backend/app/services/rule_engine.py`                        | T5-BE1, T5-SEC1    |
| `backend/app/services/normalizer.py`                         | T5-DATA1, T5-BE1   |
| `backend/app/services/enrichment.py`, `threat_feeds.py`      | T5-SEC1, T5-BE1    |
| `backend/app/api/v1/cases.py`, `alerts.py`                   | T5-DEV1            |
| `backend/app/services/notifications.py`, `sla.py`, `scheduler.py` | T5-DEV1, T5-BE1 |
| `backend/app/services/vuln_ingest.py`                        | T5-SEC1, T5-DEV1   |
| `backend/app/services/compliance.py`                         | T5-SEC1            |
| `backend/app/services/kpi.py`                                | T5-DATA1           |
| `backend/app/services/audit_chain.py`                        | T5-SEC1, T5-BE1    |
| `backend/app/services/queue.py`, `worker.py`                 | T5-BE1             |
| `backend/alembic/`, `app/seed.py`                            | T5-BE1, T5-QA1     |
| `frontend/src/`                                              | T5-FE1             |
| `frontend/src/pages/Dashboard/`                              | T5-FE1, T5-DATA1   |
| `backend/tests/`, `frontend/src/test/`, `.github/workflows/` | T5-QA1             |
| `docs/THREAT_MODEL.md`                                       | T5-SEC1            |

Update this table as the team assigns ongoing feature ownership.
