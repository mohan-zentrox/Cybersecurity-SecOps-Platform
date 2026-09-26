"""
Vulnerability scan ingestion.

FRD ref: FRD-VULN-02 — scanner exports are parsed into `Vulnerability`
rows using the same shape as the event pipeline: **parse -> validate ->
persist**, with malformed findings counted and reported rather than
silently dropped.

Supported formats
-----------------
  * ``nessus``  — Tenable ``.nessus`` XML. Reads ``ReportHost`` /
                  ``ReportItem`` elements.
  * ``csv``     — generic scanner CSV (Qualys-style). Column names are
                  matched case-insensitively against a small alias table,
                  so exports from different tools usually work unchanged.

XML is parsed with ``defusedxml``. Scanner files are attacker-influenced
input (anyone who can run a scan can shape the output), so entity expansion
and external DTD fetching must not be available to them.
"""

import csv
import io
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# defusedxml, not the stdlib parser: scan files are attacker-influenced input
# (anyone who can run a scan shapes the output), and the stdlib parser is
# vulnerable to entity-expansion and external-DTD attacks. It is a hard
# dependency rather than an optional import precisely so there is no silent
# fallback to the unsafe parser.
from defusedxml.ElementTree import fromstring as _xml_fromstring
from sqlalchemy.orm import Session

from app.models.vulnerability import Asset, RemediationStatus, Vulnerability

log = logging.getLogger("aegis.vuln_ingest")

XML_PARSER = "defusedxml"

# Nessus severity integers -> our severity vocabulary.
_NESSUS_SEVERITY = {"0": "low", "1": "low", "2": "medium", "3": "high", "4": "critical"}

_CSV_ALIASES: dict[str, tuple[str, ...]] = {
    "hostname": ("hostname", "host", "dns name", "asset", "asset name", "target"),
    "ip": ("ip", "ip address", "ipv4", "host ip", "address"),
    "cve": ("cve", "cve id", "cve_id", "cves"),
    "title": ("title", "name", "plugin name", "vulnerability", "qid title", "threat"),
    "description": ("description", "synopsis", "details", "diagnosis"),
    "severity": ("severity", "risk", "risk factor", "criticality"),
    "cvss": ("cvss", "cvss score", "cvss3 base score", "cvss_base_score", "base score"),
    "cvss_vector": ("cvss vector", "cvss3 vector", "vector"),
    "solution": ("solution", "remediation", "fix", "recommendation"),
    "port": ("port",),
    "protocol": ("protocol", "proto"),
}

_SEVERITY_WORDS = {
    "critical": "critical",
    "urgent": "critical",
    "5": "critical",
    "high": "high",
    "4": "high",
    "serious": "high",
    "medium": "medium",
    "moderate": "medium",
    "3": "medium",
    "low": "low",
    "minimal": "low",
    "2": "low",
    "1": "low",
    "0": "low",
    "info": "low",
    "informational": "low",
    "none": "low",
}


class ScanParseError(Exception):
    pass


@dataclass
class ParsedFinding:
    hostname: str
    ip_address: str | None = None
    cve_id: str | None = None
    title: str = ""
    description: str = ""
    severity: str = "medium"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    solution: str = ""
    port: int | None = None
    protocol: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanIngestResult:
    scanner: str
    imported: int = 0
    updated: int = 0
    failed: int = 0
    assets_touched: int = 0
    errors: list[str] = field(default_factory=list)


def _normalize_severity(value: Any) -> str:
    return _SEVERITY_WORDS.get(str(value or "").strip().lower(), "medium")


def _to_float(value: Any) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_nessus(content: bytes) -> list[ParsedFinding]:
    """Parse a Tenable .nessus XML export."""
    try:
        root = _xml_fromstring(content)
    except Exception as exc:  # noqa: BLE001 - any XML failure is a parse failure
        raise ScanParseError(f"invalid Nessus XML: {exc}") from exc

    findings: list[ParsedFinding] = []
    for host in root.iter("ReportHost"):
        hostname = host.get("name") or "unknown"
        ip_address = None
        for prop in host.iter("tag"):
            if prop.get("name") == "host-ip":
                ip_address = (prop.text or "").strip() or None
            elif prop.get("name") in ("host-fqdn", "hostname") and prop.text:
                hostname = prop.text.strip()

        for item in host.iter("ReportItem"):
            severity = _NESSUS_SEVERITY.get(item.get("severity", "2"), "medium")
            if item.get("severity") == "0":
                continue  # informational plugin output, not a finding

            def _text(tag: str) -> str:
                node = item.find(tag)
                return (node.text or "").strip() if node is not None and node.text else ""

            cve_node = item.find("cve")
            findings.append(
                ParsedFinding(
                    hostname=hostname,
                    ip_address=ip_address,
                    cve_id=(cve_node.text or "").strip() if cve_node is not None and cve_node.text else None,
                    title=item.get("pluginName") or _text("plugin_name") or "Unnamed finding",
                    description=_text("description")[:4000],
                    severity=severity,
                    cvss_score=_to_float(_text("cvss3_base_score") or _text("cvss_base_score")),
                    cvss_vector=(_text("cvss3_vector") or _text("cvss_vector") or None),
                    solution=_text("solution")[:4000],
                    port=_to_int(item.get("port")),
                    protocol=item.get("protocol"),
                    raw={"plugin_id": item.get("pluginID"), "plugin_family": item.get("pluginFamily")},
                )
            )
    return findings


def _csv_value(row: dict[str, str], key: str) -> str:
    for alias in _CSV_ALIASES[key]:
        for column, value in row.items():
            if column and column.strip().lower() == alias:
                return (value or "").strip()
    return ""


def parse_csv(content: bytes) -> list[ParsedFinding]:
    """Parse a generic/Qualys-style scanner CSV."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ScanParseError("CSV has no header row")

    findings: list[ParsedFinding] = []
    for row in reader:
        hostname = _csv_value(row, "hostname")
        ip_address = _csv_value(row, "ip")
        if not hostname and not ip_address:
            continue  # nothing to hang the finding off
        title = _csv_value(row, "title") or "Unnamed finding"
        findings.append(
            ParsedFinding(
                hostname=hostname or ip_address,
                ip_address=ip_address or None,
                cve_id=(_csv_value(row, "cve").split(",")[0].strip() or None),
                title=title[:512],
                description=_csv_value(row, "description")[:4000],
                severity=_normalize_severity(_csv_value(row, "severity")),
                cvss_score=_to_float(_csv_value(row, "cvss")),
                cvss_vector=_csv_value(row, "cvss_vector") or None,
                solution=_csv_value(row, "solution")[:4000],
                port=_to_int(_csv_value(row, "port")),
                protocol=_csv_value(row, "protocol") or None,
                raw=dict(row),
            )
        )
    return findings


PARSERS = {"nessus": parse_nessus, "csv": parse_csv}


def detect_scanner(filename: str, content: bytes) -> str:
    lowered = filename.lower()
    if lowered.endswith(".nessus") or lowered.endswith(".xml"):
        return "nessus"
    if lowered.endswith(".csv"):
        return "csv"
    if content[:512].lstrip().startswith(b"<"):
        return "nessus"
    return "csv"


def _get_or_create_asset(db: Session, finding: ParsedFinding) -> tuple[Asset, bool]:
    query = db.query(Asset).filter(Asset.hostname == finding.hostname)
    query = query.filter(Asset.ip_address == finding.ip_address)
    asset = query.first()
    if asset is not None:
        return asset, False
    asset = Asset(hostname=finding.hostname, ip_address=finding.ip_address)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset, True


def ingest_findings(db: Session, findings: list[ParsedFinding], scanner: str) -> ScanIngestResult:
    """Upsert parsed findings. Re-importing the same scan refreshes, never duplicates."""
    result = ScanIngestResult(scanner=scanner)
    touched_assets: set[int] = set()
    now = datetime.now(timezone.utc)

    for finding in findings:
        try:
            asset, _ = _get_or_create_asset(db, finding)
            touched_assets.add(asset.id)

            existing = (
                db.query(Vulnerability)
                .filter(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.cve_id == finding.cve_id,
                    Vulnerability.title == finding.title,
                )
                .first()
            )
            if existing is not None:
                existing.last_seen_at = now
                existing.severity = finding.severity
                existing.cvss_score = finding.cvss_score if finding.cvss_score is not None else existing.cvss_score
                existing.scanner = scanner
                # A finding that reappears in a later scan is not remediated.
                if existing.remediation_status == RemediationStatus.REMEDIATED:
                    existing.remediation_status = RemediationStatus.OPEN
                    existing.remediated_at = None
                db.commit()
                result.updated += 1
                continue

            db.add(
                Vulnerability(
                    asset_id=asset.id,
                    cve_id=finding.cve_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    cvss_score=finding.cvss_score,
                    cvss_vector=finding.cvss_vector,
                    solution=finding.solution,
                    port=finding.port,
                    protocol=finding.protocol,
                    scanner=scanner,
                    discovered_at=now,
                    last_seen_at=now,
                    raw=finding.raw,
                )
            )
            db.commit()
            result.imported += 1
        except Exception as exc:  # noqa: BLE001 - one bad row must not abort the import
            db.rollback()
            result.failed += 1
            if len(result.errors) < 20:
                result.errors.append(f"{finding.hostname}/{finding.title}: {exc}")

    result.assets_touched = len(touched_assets)
    log.info(
        "vulnerability scan ingested",
        extra={
            "aegis.scanner": scanner,
            "aegis.imported": result.imported,
            "aegis.updated": result.updated,
            "aegis.failed": result.failed,
        },
    )
    return result
