"""
SCAFFOLD ONLY — Vulnerability scan ingestion.

FRD ref: FRD-VULN-01/02 (vulnerability management integration).

TODO(FRD-VULN-01): Define `Asset` and `Vulnerability` models (CVE id,
    CVSS score/vector, affected asset, discovered_at, remediation status)
    plus an Alembic migration. `Asset` should be shareable with future
    asset-inventory features referenced elsewhere in the SRS.
TODO(FRD-VULN-02): Implement a parser for at least one common scanner
    export format (e.g. Nessus .nessus XML, Qualys CSV, or the generic
    OVAL/ARF formats) that maps findings onto the `Vulnerability` model —
    mirror the ECS-normalization pattern in services/normalizer.py:
    parse -> validate -> persist, with a dead-letter path for malformed
    scan files.
TODO(FRD-VULN-03): Add POST /api/v1/vulnerabilities/ingest (multipart file
    upload) and GET /api/v1/vulnerabilities with severity/asset filters,
    role-gated to security-lead/admin.
TODO(FRD-VULN-04): Cross-link vulnerabilities to Cases so a critical CVE
    on an internet-facing asset can be promoted the same way an Alert is
    promoted today (see api/v1/alerts.py::promote_alerts_to_case for the
    pattern to follow).
"""

# Intentionally no implementation — see TODOs above.
