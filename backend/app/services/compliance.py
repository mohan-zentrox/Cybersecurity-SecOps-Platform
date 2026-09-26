"""
Compliance evidence collection and report generation.

FRD ref: FRD-COMP-01/02 — the useful observation is that this platform
*already produces* most of the evidence an auditor asks for. The audit
chain proves activity logging is tamper-evident; case SLA data proves
incidents are responded to within a defined window; the detection rule
inventory proves monitoring coverage exists. Each framework control is
therefore bound to an **evidence collector**: a function that runs the
relevant query and returns a pass/fail verdict plus the figures backing it.

Adding a control is a row in `compliance_controls` pointing at a collector
key; adding a *kind* of evidence is a new function in EVIDENCE_COLLECTORS.

Reports render to self-contained HTML (no external CSS/JS), which prints
to PDF from any browser. That deliberately avoids a WeasyPrint/Cairo
native-dependency chain in the container image.
"""

import html
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.audit import AuditEvent
from app.models.case import Case, CaseStatus
from app.models.compliance import (
    ComplianceControl,
    ComplianceReport,
    ControlVerdict,
    Framework,
    ReportStatus,
)
from app.models.notification import DeliveryStatus, NotificationDelivery
from app.models.rule import DetectionRule
from app.models.user import User
from app.models.vulnerability import RemediationStatus, Vulnerability
from app.services.audit_chain import verify_chain

log = logging.getLogger("aegis.compliance")


@dataclass
class Evidence:
    verdict: str
    summary: str
    metrics: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Evidence collectors. Each takes (db, period_start, period_end).
# --------------------------------------------------------------------------


def _audit_chain_integrity(db: Session, start: datetime, end: datetime) -> Evidence:
    result = verify_chain(db)
    in_period = (
        db.query(func.count(AuditEvent.id))
        .filter(AuditEvent.timestamp >= start, AuditEvent.timestamp <= end)
        .scalar()
    )
    return Evidence(
        verdict=ControlVerdict.PASS if result.intact else ControlVerdict.FAIL,
        summary=(
            f"Hash chain verified across {result.total_events} audit events; integrity intact."
            if result.intact
            else f"Audit chain BROKEN at event {result.first_broken_event_id}: {result.reason}"
        ),
        metrics={
            "audit_events_total": result.total_events,
            "audit_events_in_period": int(in_period),
            "chain_intact": result.intact,
            "first_broken_event_id": result.first_broken_event_id,
        },
    )


def _activity_logging_coverage(db: Session, start: datetime, end: datetime) -> Evidence:
    rows = (
        db.query(AuditEvent.action, func.count(AuditEvent.id))
        .filter(AuditEvent.timestamp >= start, AuditEvent.timestamp <= end)
        .group_by(AuditEvent.action)
        .all()
    )
    by_action = {action: int(count) for action, count in rows}
    required = {"login_success", "login_failed"}
    covered = required & set(by_action)
    return Evidence(
        verdict=ControlVerdict.PASS if covered else ControlVerdict.FAIL,
        summary=(
            f"{sum(by_action.values())} privileged actions logged across {len(by_action)} action types."
            if covered
            else "No authentication events were logged in the reporting period."
        ),
        metrics={"actions_logged": sum(by_action.values()), "by_action": by_action},
    )


def _access_control_rbac(db: Session, start: datetime, end: datetime) -> Evidence:
    rows = db.query(User.role, func.count(User.id)).filter(User.is_active.is_(True)).group_by(User.role).all()
    by_role = {role: int(count) for role, count in rows}
    admins = by_role.get("admin", 0)
    denials = (
        db.query(func.count(AuditEvent.id))
        .filter(AuditEvent.action == "login_failed", AuditEvent.timestamp >= start, AuditEvent.timestamp <= end)
        .scalar()
    )
    # An access-control regime with every user an admin is not least-privilege.
    total_users = sum(by_role.values())
    least_privilege = total_users > 0 and admins < total_users
    return Evidence(
        verdict=ControlVerdict.PASS if least_privilege else ControlVerdict.FAIL,
        summary=(
            f"{total_users} active users across {len(by_role)} roles; {admins} administrator(s)."
            if least_privilege
            else "Every active user holds the admin role — least privilege is not enforced."
        ),
        metrics={"active_users": total_users, "by_role": by_role, "failed_logins_in_period": int(denials)},
    )


def _incident_response_sla(db: Session, start: datetime, end: datetime) -> Evidence:
    cases = db.query(Case).filter(Case.created_at >= start, Case.created_at <= end).all()
    total = len(cases)
    breached = sum(1 for c in cases if c.sla_breached)
    rate = (breached / total) if total else 0.0
    # Documented objective: at least 90% of incidents handled within SLA.
    return Evidence(
        verdict=ControlVerdict.PASS if rate <= 0.10 else ControlVerdict.FAIL,
        summary=(
            f"{total - breached}/{total} incidents closed within SLA ({(1 - rate) * 100:.1f}% compliance)."
            if total
            else "No incidents were raised in the reporting period."
        ),
        metrics={
            "cases_total": total,
            "cases_breached": breached,
            "sla_compliance_rate": round(1 - rate, 4),
            "cases_closed": sum(1 for c in cases if c.status == CaseStatus.CLOSED),
        },
    )


def _monitoring_coverage(db: Session, start: datetime, end: datetime) -> Evidence:
    enabled = db.query(func.count(DetectionRule.id)).filter(DetectionRule.enabled.is_(True)).scalar()
    techniques = (
        db.query(func.count(func.distinct(DetectionRule.mitre_technique_id)))
        .filter(DetectionRule.enabled.is_(True), DetectionRule.mitre_technique_id.isnot(None))
        .scalar()
    )
    alerts = (
        db.query(func.count(Alert.id)).filter(Alert.created_at >= start, Alert.created_at <= end).scalar()
    )
    return Evidence(
        verdict=ControlVerdict.PASS if int(enabled) > 0 else ControlVerdict.FAIL,
        summary=(
            f"{enabled} detection rules active covering {techniques} MITRE ATT&CK technique(s); "
            f"{alerts} alerts raised in period."
            if int(enabled)
            else "No detection rules are enabled — security monitoring is not operating."
        ),
        metrics={
            "rules_enabled": int(enabled),
            "mitre_techniques_covered": int(techniques),
            "alerts_in_period": int(alerts),
        },
    )


def _vulnerability_management(db: Session, start: datetime, end: datetime) -> Evidence:
    rows = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .filter(Vulnerability.remediation_status == RemediationStatus.OPEN)
        .group_by(Vulnerability.severity)
        .all()
    )
    open_by_severity = {sev: int(count) for sev, count in rows}
    open_critical = open_by_severity.get("critical", 0)
    remediated = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.remediated_at >= start, Vulnerability.remediated_at <= end)
        .scalar()
    )
    return Evidence(
        verdict=ControlVerdict.PASS if open_critical == 0 else ControlVerdict.FAIL,
        summary=(
            f"No open critical vulnerabilities; {remediated} finding(s) remediated in period."
            if open_critical == 0
            else f"{open_critical} critical vulnerabilit(ies) remain open past the remediation window."
        ),
        metrics={
            "open_by_severity": open_by_severity,
            "open_total": sum(open_by_severity.values()),
            "remediated_in_period": int(remediated),
        },
    )


def _alerting_operational(db: Session, start: datetime, end: datetime) -> Evidence:
    sent = (
        db.query(func.count(NotificationDelivery.id))
        .filter(
            NotificationDelivery.status == DeliveryStatus.SENT,
            NotificationDelivery.attempted_at >= start,
            NotificationDelivery.attempted_at <= end,
        )
        .scalar()
    )
    failed = (
        db.query(func.count(NotificationDelivery.id))
        .filter(
            NotificationDelivery.status == DeliveryStatus.FAILED,
            NotificationDelivery.attempted_at >= start,
            NotificationDelivery.attempted_at <= end,
        )
        .scalar()
    )
    total = int(sent) + int(failed)
    return Evidence(
        verdict=ControlVerdict.PASS if int(failed) == 0 else ControlVerdict.FAIL,
        summary=(
            f"{sent} security notifications delivered with no failures."
            if int(failed) == 0
            else f"{failed} of {total} notification deliveries failed — alert routing is unreliable."
        ),
        metrics={"delivered": int(sent), "failed": int(failed)},
    )


EVIDENCE_COLLECTORS: dict[str, Callable[[Session, datetime, datetime], Evidence]] = {
    "audit_chain_integrity": _audit_chain_integrity,
    "activity_logging_coverage": _activity_logging_coverage,
    "access_control_rbac": _access_control_rbac,
    "incident_response_sla": _incident_response_sla,
    "monitoring_coverage": _monitoring_coverage,
    "vulnerability_management": _vulnerability_management,
    "alerting_operational": _alerting_operational,
}


# --------------------------------------------------------------------------
# Default control catalogue, seeded on first run.
# --------------------------------------------------------------------------

DEFAULT_CONTROLS: list[dict[str, str]] = [
    # SOC 2 Trust Services Criteria
    {
        "framework": Framework.SOC2,
        "control_id": "CC6.1",
        "title": "Logical access controls restrict access to authorized users",
        "description": "Role-based access control is enforced on every privileged operation.",
        "evidence_collector": "access_control_rbac",
    },
    {
        "framework": Framework.SOC2,
        "control_id": "CC7.2",
        "title": "System components are monitored to detect anomalies",
        "description": "Detection rules evaluate ingested telemetry and raise alerts.",
        "evidence_collector": "monitoring_coverage",
    },
    {
        "framework": Framework.SOC2,
        "control_id": "CC7.3",
        "title": "Security events are evaluated and responded to",
        "description": "Alerts are triaged into cases and closed within a severity-based SLA.",
        "evidence_collector": "incident_response_sla",
    },
    {
        "framework": Framework.SOC2,
        "control_id": "CC7.4",
        "title": "Identified incidents are communicated to responsible parties",
        "description": "Notification channels deliver alerts to on-call responders.",
        "evidence_collector": "alerting_operational",
    },
    {
        "framework": Framework.SOC2,
        "control_id": "CC4.1",
        "title": "Audit records are protected from modification",
        "description": "The audit log is hash-chained; any edit or deletion is detectable.",
        "evidence_collector": "audit_chain_integrity",
    },
    # ISO/IEC 27001:2022 Annex A
    {
        "framework": Framework.ISO27001,
        "control_id": "A.8.15",
        "title": "Logging",
        "description": "Activity logs recording user actions are produced and retained.",
        "evidence_collector": "activity_logging_coverage",
    },
    {
        "framework": Framework.ISO27001,
        "control_id": "A.8.16",
        "title": "Monitoring activities",
        "description": "Networks and systems are monitored for anomalous behaviour.",
        "evidence_collector": "monitoring_coverage",
    },
    {
        "framework": Framework.ISO27001,
        "control_id": "A.5.25",
        "title": "Assessment and decision on information security events",
        "description": "Security events are assessed and classified as incidents.",
        "evidence_collector": "incident_response_sla",
    },
    {
        "framework": Framework.ISO27001,
        "control_id": "A.8.8",
        "title": "Management of technical vulnerabilities",
        "description": "Vulnerabilities are identified, evaluated, and remediated.",
        "evidence_collector": "vulnerability_management",
    },
    {
        "framework": Framework.ISO27001,
        "control_id": "A.5.15",
        "title": "Access control",
        "description": "Access to information is restricted per an access control policy.",
        "evidence_collector": "access_control_rbac",
    },
    # PCI DSS v4.0
    {
        "framework": Framework.PCI_DSS,
        "control_id": "10.2",
        "title": "Audit logs capture all individual user access and privileged actions",
        "description": "Every privileged action is written to the audit log.",
        "evidence_collector": "activity_logging_coverage",
    },
    {
        "framework": Framework.PCI_DSS,
        "control_id": "10.3",
        "title": "Audit logs are protected from destruction and unauthorized modification",
        "description": "Hash chaining makes tampering with historical audit rows detectable.",
        "evidence_collector": "audit_chain_integrity",
    },
    {
        "framework": Framework.PCI_DSS,
        "control_id": "10.7",
        "title": "Failures of critical security control systems are detected and responded to",
        "description": "Alert delivery failures and SLA breaches are surfaced and actioned.",
        "evidence_collector": "alerting_operational",
    },
    {
        "framework": Framework.PCI_DSS,
        "control_id": "11.3",
        "title": "External and internal vulnerabilities are identified and addressed",
        "description": "Scanner findings are ingested and tracked to remediation.",
        "evidence_collector": "vulnerability_management",
    },
    {
        "framework": Framework.PCI_DSS,
        "control_id": "12.10",
        "title": "Suspected and confirmed security incidents are responded to immediately",
        "description": "Incident response follows a documented, SLA-bound workflow.",
        "evidence_collector": "incident_response_sla",
    },
]


def seed_default_controls(db: Session) -> int:
    """Insert any missing default controls. Idempotent; returns the number added."""
    added = 0
    for spec in DEFAULT_CONTROLS:
        exists = (
            db.query(ComplianceControl)
            .filter(
                ComplianceControl.framework == spec["framework"],
                ComplianceControl.control_id == spec["control_id"],
            )
            .first()
        )
        if exists:
            continue
        db.add(ComplianceControl(**spec))
        added += 1
    if added:
        db.commit()
    return added


def generate_report(
    db: Session,
    *,
    framework: str,
    period_start: datetime,
    period_end: datetime,
    generated_by: str,
) -> ComplianceReport:
    """Run every enabled control for `framework` and persist an immutable report."""
    report = ComplianceReport(
        framework=framework,
        period_start=period_start,
        period_end=period_end,
        status=ReportStatus.RUNNING,
        generated_by=generated_by,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    try:
        controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework == framework, ComplianceControl.enabled.is_(True))
            .order_by(ComplianceControl.control_id.asc())
            .all()
        )
        if not controls:
            raise ValueError(f"No enabled controls are configured for framework {framework!r}")

        results = []
        for control in controls:
            collector = EVIDENCE_COLLECTORS.get(control.evidence_collector)
            if collector is None:
                evidence = Evidence(
                    verdict=ControlVerdict.NOT_APPLICABLE,
                    summary=f"No evidence collector registered under {control.evidence_collector!r}",
                )
            else:
                try:
                    evidence = collector(db, period_start, period_end)
                except Exception as exc:  # noqa: BLE001 - one broken collector must not void the report
                    log.exception("compliance evidence collector failed", extra={"aegis.control": control.control_id})
                    evidence = Evidence(verdict=ControlVerdict.FAIL, summary=f"Collector error: {exc}")

            results.append(
                {
                    "control_id": control.control_id,
                    "title": control.title,
                    "description": control.description,
                    "collector": control.evidence_collector,
                    "verdict": evidence.verdict,
                    "summary": evidence.summary,
                    "metrics": evidence.metrics,
                }
            )

        passed = sum(1 for r in results if r["verdict"] == ControlVerdict.PASS)
        failed = sum(1 for r in results if r["verdict"] == ControlVerdict.FAIL)

        report.results = {"controls": results}
        report.controls_total = len(results)
        report.controls_passed = passed
        report.controls_failed = failed
        report.rendered_html = render_report_html(report, results)
        report.status = ReportStatus.COMPLETED
        report.completed_at = datetime.now(timezone.utc)
    except Exception as exc:  # noqa: BLE001 - surface the failure on the row, do not 500
        report.status = ReportStatus.FAILED
        report.error_message = str(exc)[:2000]
        report.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(report)
    return report


_VERDICT_COLOR = {
    ControlVerdict.PASS: "#10b981",
    ControlVerdict.FAIL: "#ef4444",
    ControlVerdict.NOT_APPLICABLE: "#94a3b8",
}


def render_report_html(report: ComplianceReport, results: list[dict[str, Any]]) -> str:
    """Render a self-contained HTML artifact (prints to PDF from any browser)."""
    esc = html.escape

    rows = []
    for item in results:
        metrics = "".join(
            f"<li><code>{esc(str(k))}</code>: {esc(str(v))}</li>" for k, v in (item["metrics"] or {}).items()
        )
        rows.append(
            f"""
        <tr>
          <td class="cid">{esc(item['control_id'])}</td>
          <td>
            <div class="title">{esc(item['title'])}</div>
            <div class="desc">{esc(item['description'])}</div>
          </td>
          <td><span class="badge" style="background:{_VERDICT_COLOR.get(item['verdict'], '#94a3b8')}">
            {esc(item['verdict'].replace('_', ' ').upper())}</span></td>
          <td>
            <div>{esc(item['summary'])}</div>
            <ul class="metrics">{metrics}</ul>
          </td>
        </tr>"""
        )

    pass_rate = (report.controls_passed / report.controls_total * 100) if report.controls_total else 0.0

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{esc(report.framework)} Compliance Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #0f172a; }}
  h1 {{ margin-bottom: .25rem; }}
  .meta {{ color: #475569; font-size: .9rem; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 2rem; padding: 1rem; background: #f1f5f9; border-radius: 8px; margin-bottom: 1.5rem; }}
  .summary div span {{ display: block; font-size: 1.6rem; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
  th, td {{ border-bottom: 1px solid #e2e8f0; padding: .6rem; text-align: left; vertical-align: top; }}
  th {{ background: #f8fafc; }}
  .cid {{ font-family: ui-monospace, monospace; white-space: nowrap; }}
  .title {{ font-weight: 600; }}
  .desc {{ color: #64748b; font-size: .85rem; }}
  .badge {{ color: #fff; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }}
  .metrics {{ margin: .4rem 0 0; padding-left: 1.1rem; color: #475569; font-size: .8rem; }}
  footer {{ margin-top: 2rem; color: #94a3b8; font-size: .8rem; }}
</style></head><body>
  <h1>{esc(report.framework)} Compliance Report</h1>
  <div class="meta">
    Reporting period {esc(report.period_start.isoformat())} &rarr; {esc(report.period_end.isoformat())}<br>
    Generated by {esc(report.generated_by)} via Project Aegis
  </div>
  <div class="summary">
    <div>Controls assessed<span>{report.controls_total}</span></div>
    <div>Passed<span style="color:#10b981">{report.controls_passed}</span></div>
    <div>Failed<span style="color:#ef4444">{report.controls_failed}</span></div>
    <div>Pass rate<span>{pass_rate:.0f}%</span></div>
  </div>
  <table>
    <thead><tr><th>Control</th><th>Requirement</th><th>Verdict</th><th>Evidence</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <footer>
    Evidence is collected automatically from Project Aegis operational data at generation time.
    This report is immutable; regenerating produces a new report rather than altering this one.
  </footer>
</body></html>"""
