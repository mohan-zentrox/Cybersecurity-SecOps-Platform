"""
Vulnerability scan ingestion (FRD-VULN-01..04) and compliance reporting
(FRD-COMP-01/02).
"""

import io
from datetime import datetime, timedelta, timezone

from app.models.case import Case
from app.models.compliance import ControlVerdict
from app.models.vulnerability import Asset, RemediationStatus, Vulnerability
from app.services.compliance import generate_report, seed_default_controls
from app.services.vuln_ingest import detect_scanner, parse_csv, parse_nessus
from tests.conftest import auth_headers

NESSUS_XML = b"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="scan">
    <ReportHost name="10.10.1.11">
      <HostProperties>
        <tag name="host-ip">10.10.1.11</tag>
        <tag name="host-fqdn">web-prod-01</tag>
      </HostProperties>
      <ReportItem port="443" protocol="tcp" severity="4" pluginID="1001" pluginName="OpenSSH RCE">
        <description>Remote code execution in sshd.</description>
        <solution>Upgrade OpenSSH.</solution>
        <cve>CVE-2024-6387</cve>
        <cvss3_base_score>8.1</cvss3_base_score>
      </ReportItem>
      <ReportItem port="80" protocol="tcp" severity="2" pluginID="1002" pluginName="Weak TLS ciphers">
        <description>Server supports weak ciphers.</description>
        <solution>Disable CBC ciphers.</solution>
        <cvss_base_score>5.3</cvss_base_score>
      </ReportItem>
      <ReportItem port="0" protocol="tcp" severity="0" pluginID="1003" pluginName="Host info">
        <description>Informational only.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

QUALYS_CSV = b"""Host,IP,CVE,Title,Severity,CVSS,Solution
db-prod-01,10.10.2.21,CVE-2024-1597,PostgreSQL JDBC SQL injection,Critical,9.8,Upgrade pgjdbc
db-prod-01,10.10.2.21,CVE-2023-38545,curl SOCKS5 heap overflow,High,8.8,Upgrade curl
jump-01,10.10.0.5,,Outdated TLS configuration,Medium,5.0,Harden TLS
"""


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def test_nessus_parser_reads_findings_and_drops_informational():
    findings = parse_nessus(NESSUS_XML)

    assert len(findings) == 2  # severity 0 is informational, not a finding
    critical = findings[0]
    assert critical.hostname == "web-prod-01"
    assert critical.ip_address == "10.10.1.11"
    assert critical.cve_id == "CVE-2024-6387"
    assert critical.severity == "critical"
    assert critical.cvss_score == 8.1
    assert critical.port == 443


def test_nessus_parser_rejects_malformed_xml():
    import pytest

    from app.services.vuln_ingest import ScanParseError

    with pytest.raises(ScanParseError):
        parse_nessus(b"<not-valid-xml")


def test_csv_parser_matches_columns_case_insensitively():
    findings = parse_csv(QUALYS_CSV)

    assert len(findings) == 3
    assert findings[0].hostname == "db-prod-01"
    assert findings[0].cve_id == "CVE-2024-1597"
    assert findings[0].severity == "critical"  # "Critical" normalized
    assert findings[0].cvss_score == 9.8
    assert findings[2].cve_id is None  # empty CVE column


def test_scanner_autodetection():
    assert detect_scanner("scan.nessus", NESSUS_XML) == "nessus"
    assert detect_scanner("export.csv", QUALYS_CSV) == "csv"
    assert detect_scanner("unknown.dat", NESSUS_XML) == "nessus"  # sniffed from content


# ---------------------------------------------------------------------------
# Ingestion API
# ---------------------------------------------------------------------------


def _upload(client, headers, content: bytes, filename: str):
    return client.post(
        "/api/v1/vulnerabilities/ingest",
        headers=headers,
        files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
    )


def test_scan_upload_creates_assets_and_vulnerabilities(client, admin_user, db):
    headers = auth_headers(client, "admin1")

    resp = _upload(client, headers, NESSUS_XML, "scan.nessus")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scanner"] == "nessus"
    assert body["imported"] == 2
    assert body["failed"] == 0
    assert body["assets_touched"] == 1

    assert db.query(Asset).count() == 1
    assert db.query(Vulnerability).count() == 2


def test_reimporting_the_same_scan_updates_instead_of_duplicating(client, admin_user, db):
    headers = auth_headers(client, "admin1")

    first = _upload(client, headers, NESSUS_XML, "scan.nessus").json()
    second = _upload(client, headers, NESSUS_XML, "scan.nessus").json()

    assert first["imported"] == 2
    assert second["imported"] == 0
    assert second["updated"] == 2
    assert db.query(Vulnerability).count() == 2


def test_a_reappearing_finding_is_reopened(client, admin_user, db):
    """Marking something remediated does not make it so if the scanner
    still reports it."""
    headers = auth_headers(client, "admin1")
    _upload(client, headers, NESSUS_XML, "scan.nessus")

    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == "CVE-2024-6387").one()
    client.patch(
        f"/api/v1/vulnerabilities/{vuln.id}/status",
        headers=headers,
        json={"remediation_status": "remediated"},
    )
    db.refresh(vuln)
    assert vuln.remediation_status == RemediationStatus.REMEDIATED

    _upload(client, headers, NESSUS_XML, "scan.nessus")
    db.refresh(vuln)
    assert vuln.remediation_status == RemediationStatus.OPEN
    assert vuln.remediated_at is None


def test_csv_upload_and_filtering(client, admin_user, db):
    headers = auth_headers(client, "admin1")
    _upload(client, headers, QUALYS_CSV, "qualys.csv")

    critical = client.get("/api/v1/vulnerabilities?severity=critical", headers=headers).json()
    assert critical["total"] == 1
    assert critical["items"][0]["cve_id"] == "CVE-2024-1597"

    high_cvss = client.get("/api/v1/vulnerabilities?min_cvss=8", headers=headers).json()
    assert high_cvss["total"] == 2


def test_empty_upload_is_rejected(client, admin_user, db):
    resp = _upload(client, auth_headers(client, "admin1"), b"", "empty.csv")
    assert resp.status_code == 400


def test_analyst_cannot_upload_scans(client, analyst_user, db):
    resp = _upload(client, auth_headers(client, "analyst1"), QUALYS_CSV, "q.csv")
    assert resp.status_code == 403


def test_vulnerabilities_promote_to_a_case(client, admin_user, db):
    headers = auth_headers(client, "admin1")
    _upload(client, headers, QUALYS_CSV, "qualys.csv")
    ids = [v["id"] for v in client.get("/api/v1/vulnerabilities", headers=headers).json()["items"][:2]]

    resp = client.post(
        "/api/v1/vulnerabilities/promote",
        headers=headers,
        json={"vulnerability_ids": ids, "title": "Patch cycle: critical CVEs"},
    )
    assert resp.status_code == 201, resp.text
    case_id = resp.json()["id"]
    assert resp.json()["severity"] == "critical"  # highest severity wins

    detail = client.get(f"/api/v1/cases/{case_id}", headers=headers).json()
    assert sorted(detail["vulnerability_ids"]) == sorted(ids)
    assert any(e["type"] == "vulnerability_linked" for e in detail["timeline"])

    # Promoted findings move out of the untouched backlog.
    for vuln_id in ids:
        assert (
            client.get(f"/api/v1/vulnerabilities/{vuln_id}", headers=headers).json()["remediation_status"]
            == "in_progress"
        )
    assert db.query(Case).count() == 1


# ---------------------------------------------------------------------------
# Compliance reporting
# ---------------------------------------------------------------------------


def test_seeding_controls_is_idempotent(db):
    first = seed_default_controls(db)
    second = seed_default_controls(db)
    assert first > 0
    assert second == 0


def test_report_collects_real_evidence_from_platform_data(db, analyst_user):
    seed_default_controls(db)
    now = datetime.now(timezone.utc)

    report = generate_report(
        db,
        framework="SOC2",
        period_start=now - timedelta(days=7),
        period_end=now + timedelta(minutes=1),
        generated_by="auditor",
    )

    assert report.status == "completed"
    assert report.controls_total == 5
    assert report.controls_total == report.controls_passed + report.controls_failed
    assert report.rendered_html and "SOC2 Compliance Report" in report.rendered_html

    verdicts = {c["control_id"]: c for c in report.results["controls"]}
    # The audit chain is intact on a clean database, so CC4.1 must pass and
    # must cite a real event count rather than a hard-coded string.
    assert verdicts["CC4.1"]["verdict"] == ControlVerdict.PASS
    assert "audit_events_total" in verdicts["CC4.1"]["metrics"]


def test_report_reflects_a_broken_audit_chain(db, analyst_user, client):
    """The compliance verdict is derived, not asserted: tamper with the log and
    the control flips to fail."""
    from app.models.audit import AuditEvent

    seed_default_controls(db)
    client.post("/api/v1/auth/login", json={"username": "analyst1", "password": "Str0ng-Passw0rd!"})

    row = db.query(AuditEvent).order_by(AuditEvent.id.asc()).first()
    row.actor = "somebody-else"
    db.commit()

    now = datetime.now(timezone.utc)
    report = generate_report(
        db,
        framework="SOC2",
        period_start=now - timedelta(days=1),
        period_end=now + timedelta(minutes=1),
        generated_by="auditor",
    )

    verdicts = {c["control_id"]: c for c in report.results["controls"]}
    assert verdicts["CC4.1"]["verdict"] == ControlVerdict.FAIL
    assert "BROKEN" in verdicts["CC4.1"]["summary"]


def test_report_generation_endpoint_is_role_gated(client, analyst_user, compliance_user, db):
    now = datetime.now(timezone.utc)
    payload = {
        "framework": "ISO27001",
        "period_start": (now - timedelta(days=30)).isoformat(),
        "period_end": now.isoformat(),
    }

    assert (
        client.post("/api/v1/compliance/reports", headers=auth_headers(client, "analyst1"), json=payload).status_code
        == 403
    )

    resp = client.post(
        "/api/v1/compliance/reports", headers=auth_headers(client, "compliance1"), json=payload
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["framework"] == "ISO27001"
    assert resp.json()["controls_total"] == 5


def test_report_download_returns_the_html_artifact(client, compliance_user, db):
    headers = auth_headers(client, "compliance1")
    now = datetime.now(timezone.utc)
    report_id = client.post(
        "/api/v1/compliance/reports",
        headers=headers,
        json={
            "framework": "PCI-DSS",
            "period_start": (now - timedelta(days=30)).isoformat(),
            "period_end": now.isoformat(),
        },
    ).json()["id"]

    resp = client.get(f"/api/v1/compliance/reports/{report_id}/download", headers=headers)
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    assert "<!doctype html>" in resp.text.lower()
    assert "PCI-DSS" in resp.text


def test_inverted_reporting_period_is_rejected(client, compliance_user, db):
    now = datetime.now(timezone.utc)
    resp = client.post(
        "/api/v1/compliance/reports",
        headers=auth_headers(client, "compliance1"),
        json={
            "framework": "SOC2",
            "period_start": now.isoformat(),
            "period_end": (now - timedelta(days=1)).isoformat(),
        },
    )
    assert resp.status_code == 400
