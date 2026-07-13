"""
SCAFFOLD ONLY — Compliance report generation (SOC2 / ISO27001 / PCI-DSS).

FRD ref: FRD-COMP-01/02/03 (compliance reporting).

TODO(FRD-COMP-01): Define a `ComplianceControl` model mapping platform
    capabilities to specific framework control IDs (e.g. SOC2 CC7.2,
    ISO27001 A.12.4, PCI-DSS 10.x) and a `ComplianceEvidence` model that
    links controls to concrete artifacts already produced by this
    platform — e.g. the audit chain (services/audit_chain.py) is direct
    evidence for "system activity is logged and tamper-evident" controls.
TODO(FRD-COMP-02): Implement a report generator that queries AuditEvent,
    Case, and DetectionRule data over a reporting period and renders a
    PDF/HTML report per framework. Consider a template-per-framework
    approach (Jinja2 + WeasyPrint or similar) rather than one monolithic
    generator.
TODO(FRD-COMP-03): Expose POST /api/v1/compliance/reports (kick off async
    generation job) and GET /api/v1/compliance/reports/{id} (download),
    role-gated to the `compliance` role. Long-running generation should go
    through the same queue abstraction as event ingestion
    (services/queue.py) rather than blocking the request.
"""

# Intentionally no implementation — see TODOs above.
