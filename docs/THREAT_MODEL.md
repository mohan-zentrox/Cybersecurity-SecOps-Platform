# Project Aegis — Threat Model (STRIDE)

Scope: this platform is internal/defensive SOC tooling. It ingests security
telemetry, enriches it with threat intelligence, evaluates detection rules,
routes alerts to responders, manages the resulting investigations, ingests
vulnerability scans, and produces compliance evidence.

Owner: T5-SEC1. Review this document whenever a new external input,
outbound network call, or stored credential is introduced.

**Trust boundaries.** Three inputs are attacker-influenceable and are
treated as hostile: (1) raw event payloads on `/events/ingest`, since
anyone who can write to a log source shapes them; (2) uploaded scanner
files, since anyone who can run a scan shapes the output; (3) external
threat-intel feed responses. Two outputs reach the network on behalf of an
operator: notification dispatch and feed polling. Everything else is
authenticated, role-gated internal traffic.

---

## Auth & session (`api/v1/auth.py`, `api/v1/users.py`, `core/security.py`, `core/deps.py`)

| STRIDE | Risk | Mitigation | Residual risk |
|---|---|---|---|
| Spoofing | Credential stuffing / brute force | Per-(username, IP) sliding-window rate limiter (`core/rate_limit.py`); every attempt audited | Limiter is **in-process**, so it is per-replica rather than global. Swap in a Redis counter behind the same `RateLimiter` interface before scaling out |
| Spoofing | Weak passwords | 12-character minimum enforced at the schema layer, before the value reaches the hasher | No complexity rules, breach-corpus check, or MFA |
| Tampering | Forged session token | JWT signed HS256 with `JWT_SECRET_KEY`; the app refuses to boot in production on the default secret or one under 32 chars | — |
| Repudiation | "I didn't do that" | Every login, user mutation, and privileged action is written to the hash-chained audit log | — |
| Information Disclosure | Password exposure | bcrypt hashing; hashes never serialized (no field for them on `UserOut`); identical 401 for unknown user and wrong password, so no user enumeration | — |
| Elevation of Privilege | Role escalation from a low-priv account | Role re-checked server-side on every request via `require_roles()`, never trusted from client state. The UI hides what a role cannot use, but that is usability, not the boundary | — |
| Elevation of Privilege | Self-lockout / loss of administration | Deactivating the last active admin, or your own account, is refused | — |
| Denial of Service | Stolen token remains valid after discovery | Short token lifetime (`ACCESS_TOKEN_EXPIRE_MINUTES`) | **JWTs are stateless: there is no revocation list.** Logout is client-side only. Token lifetime is the only control — shorten it for sensitive deployments |

## Ingestion (`api/v1/events.py`, `services/normalizer.py`, `services/queue.py`, `worker.py`)

| STRIDE | Risk | Mitigation | Residual risk |
|---|---|---|---|
| Tampering | Injection via event field values | Values are stored as data (JSON columns, parameterized ORM queries), never interpolated into SQL or a shell; unparsable events are dead-lettered rather than coerced | — |
| Tampering | Log forging to hide activity, or to frame a principal | Raw payload retained alongside the normalized document for forensic comparison | Producer authenticity is not verified — any authenticated caller can submit events attributing activity to any host or user. Per-source ingest credentials are a recommended follow-up |
| Denial of Service | Ingest flooding | Batch capped at 10,000 events; queue absorbs bursts; `INGEST_MODE=worker` moves processing off the request path | **No per-source rate limit on `/events/ingest` itself** |
| Denial of Service | Dead-letter queue growth from a broken producer | Replay re-validates each payload individually, so a failed replay marks the existing row instead of inserting a second copy | An unfixed producer still grows the DLQ; monitor `dead_letter_rate` on the dashboard |
| Information Disclosure | PII or secrets inside raw payloads | Raw payload is retained deliberately for forensics | **No field-level redaction.** Review before ingesting production-sensitive sources |
| Repudiation | Events lost without trace on a crash | Redis Streams consumer groups: messages are acknowledged only after durable write, and entries orphaned by a dead worker are reclaimed via `XAUTOCLAIM` | At-least-once means a replayed batch can re-present events; `dedup_key` prevents duplicate alerts |

## Threat intel (`api/v1/threat_intel.py`, `services/enrichment.py`, `services/threat_feeds.py`)

| STRIDE | Risk | Mitigation | Residual risk |
|---|---|---|---|
| Tampering | Poisoned indicator floods the SOC with alerts (e.g. your own egress IP marked malicious) | Indicator authorship restricted to `detection-engineer`/`admin` and audited; the console warns before submission; indicators carry a confidence score rules can threshold on | A privileged mistake still causes noise. Indicators are deactivated rather than deleted so the blast radius is reversible and auditable |
| Tampering | Malicious feed response | Feed responses are parsed as data; unknown indicator types are skipped rather than trusted | A compromised feed can still inject bad indicators — bound the damage with `default_confidence` and rule thresholds |
| **Information Disclosure** | **SSRF via a feed URL** | `require_http_url()` rejects any scheme other than `http`/`https` before the request is made, so `file://`, `ftp://` and `data:` are unreachable | **No allowlist or private-IP block**: an operator-configured feed URL can still reach internal addresses. Egress-filter the deployment |
| Denial of Service | A slow or huge feed stalls the scheduler | Fetch timeout applied; a failing poll is recorded on the feed row and swallowed, so one bad feed cannot kill the loop | No response size cap |

## Detection & alerting (`services/rule_engine.py`, `api/v1/rules.py`, `api/v1/alerts.py`, `services/notifications.py`)

| STRIDE | Risk | Mitigation | Residual risk |
|---|---|---|---|
| Tampering | Rule logic altered to suppress detections | Rule mutation restricted to `detection-engineer`/`admin` and audited; a rule with alerts attached cannot be deleted, only disabled, so the alert history stays explicable | — |
| Denial of Service | Catastrophic regex in a rule condition (ReDoS) | Rule authorship is a privileged, audited action; an invalid regex is rejected at test/evaluate time with a 400 | **A valid but pathological regex can still burn CPU.** No evaluation timeout |
| Repudiation | Alert status silently changed | Transitions are state-machine enforced (invalid → 400) and audited with `from`/`to` | — |
| Repudiation | Disputed "nobody was paged" | Every dispatch attempt is recorded as a `NotificationDelivery`, including skips and failures | — |
| **Information Disclosure** | **SSRF / local file read via a webhook URL** | Same `require_http_url()` scheme allowlist; failures are captured on the delivery row rather than raised | Same private-IP caveat as feeds |
| Information Disclosure | Webhook URL is credential-equivalent — anyone holding it can post to the destination | Channel management restricted to `admin`; the audit entry for a channel update records **field names only, never the config values** | Config is stored unencrypted in the database. Use a secrets manager for high-value destinations |
| Information Disclosure | Alert content leaking to a third-party chat service | Severity floor per channel limits what is sent | Payload content is not redacted |

## Case management (`api/v1/cases.py`)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Editing case history after the fact | `CaseTimelineEvent` rows are append-only — no update or delete endpoint exists |
| Repudiation | Disputed SLA compliance | `sla_due_at` is fixed at creation from severity; breaches are recorded once by the sweeper with `actor="system"`, audited, and written to the timeline |
| Repudiation | Ambiguous closure | Closing requires a disposition, so "closed" always carries a recorded reason |

## Vulnerability ingestion (`api/v1/vulnerabilities.py`, `services/vuln_ingest.py`)

| STRIDE | Risk | Mitigation | Residual risk |
|---|---|---|---|
| **Tampering** | **XXE / billion-laughs via uploaded scanner XML** | Parsed with `defusedxml`, which disables entity expansion and external DTD fetching. It is a **hard dependency with no stdlib fallback**, so an install cannot silently regress to the vulnerable parser | — |
| Denial of Service | Oversized upload | 50 MiB cap enforced in the route; nginx allows slightly more so the API returns its own explanatory 413 | Parsing is synchronous and holds a worker for the duration of a large file |
| Denial of Service | One malformed row aborts an entire import | Per-finding error handling with rollback; failures are counted and the first 20 reported | — |
| Tampering | Forged scan hiding a real vulnerability | Upload restricted to `detection-engineer`/`admin` and audited; a finding that reappears in a later scan is automatically reopened even if previously marked remediated | Scanner output authenticity is not verified |
| Information Disclosure | Scan output reveals exploitable weaknesses | Reads require authentication; uploads require a privileged role | Findings are readable by every authenticated role |

## Compliance reporting (`api/v1/compliance.py`, `services/compliance.py`)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Doctored report presented to an auditor | Reports are immutable — regenerating produces a new row and never mutates an old one; generation is audited with the pass/fail counts |
| Tampering | Report claims compliance that is not real | Verdicts are **derived from live data**, not asserted. Tampering with the audit log flips the corresponding control to `fail` (covered by a test) |
| Information Disclosure | Report reveals security posture | All compliance endpoints restricted to `compliance`/`admin` |
| Denial of Service | Unbounded reporting period | Period capped at 400 days |
| Information Disclosure | XSS via injected content in the rendered HTML artifact | All interpolated values are passed through `html.escape()` |

## Audit log (`services/audit_chain.py`, `api/v1/audit.py`)

| STRIDE | Risk | Mitigation | Residual risk |
|---|---|---|---|
| Tampering | Attacker with DB access edits or deletes historical rows | Hash chain (`prev_hash` + `content_hash`) makes any in-place edit, deletion, insertion or reordering detectable via `GET /audit/verify` | **Detection, not prevention.** Apply DB-level write restrictions and off-host backups; consider periodically anchoring the head hash externally |
| Elevation of Privilege | Non-compliance roles reading the trail | All `/audit*` routes restricted to `compliance`/`admin` |  |
| Information Disclosure | Export leaks the full activity history | Export is role-gated and capped; it deliberately includes the chain hashes so an auditor can re-verify offline | — |

## Console & transport (`frontend/`, `nginx.conf`, `main.py`)

| STRIDE | Risk | Mitigation | Residual risk |
|---|---|---|---|
| Information Disclosure | Traffic sniffing | TLS termination expected at the ingress in front of the stack | **Not configured in this repo** (local dev). Terminate TLS before exposing it |
| Tampering | XSS in the console | React escapes interpolated content by default; the shipped CSP forbids inline and third-party scripts entirely | — |
| Tampering | Clickjacking | `X-Frame-Options: DENY` and `frame-ancestors 'none'` | — |
| Information Disclosure | Token theft via XSS | Strict CSP; no `dangerouslySetInnerHTML` anywhere in the console | **The session token is in `localStorage`**, so any successful XSS reads it. An httpOnly cookie with CSRF protection would be stronger |
| Spoofing | Cross-origin request forgery | Bearer tokens are not sent automatically by the browser, so classic CSRF does not apply; CORS is restricted to a configured origin list and `*` is refused in production | — |
| Tampering | Supply-chain (dependency) compromise | CI runs `bandit` (blocking), `gitleaks` (blocking), `pip-audit` and Trivy image scanning (reporting) | `pip-audit` is non-blocking pending major-version upgrades — see `.github/workflows/ci.yml` |
| Elevation of Privilege | Container escape | Backend image runs as a non-root user | Frontend image uses the stock nginx entrypoint |

## Prioritized follow-ups

1. Move the login rate limiter to Redis so it is global rather than per-replica.
2. Add JWT revocation (deny-list on logout) and refresh-token rotation.
3. Per-source ingest credentials and a per-source ingest rate limit.
4. Egress filtering, or a private-IP block, for webhook and feed URLs.
5. Field-level redaction for sensitive values in retained raw payloads.
6. Clear the `pip-audit` backlog so that gate and Trivy can become blocking.
