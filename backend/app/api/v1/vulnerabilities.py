"""
FRD ref: FRD-VULN-01..04 — scanner upload and parsing, asset inventory,
vulnerability listing with filters, remediation tracking, and promotion of
findings into a Case using the same pattern as alert promotion.

Uploads are capped and role-gated: parsing attacker-influenced XML/CSV is
the highest-risk input path in the platform (see docs/THREAT_MODEL.md).
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.case import Case, CaseStatus, CaseTimelineEvent, TimelineEventType
from app.models.user import AppRole, User
from app.models.vulnerability import Asset, RemediationStatus, ScanImport, Vulnerability
from app.schemas.case import CaseOut
from app.schemas.vulnerability import (
    AssetCreate,
    AssetOut,
    AssetUpdate,
    ScanImportOut,
    ScanIngestResponse,
    VulnerabilityDetailOut,
    VulnerabilityOut,
    VulnerabilityStatusUpdate,
    VulnPromoteRequest,
)
from app.services.audit_chain import append_audit_event
from app.services.vuln_ingest import PARSERS, ScanParseError, detect_scanner, ingest_findings

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

_VULN_MANAGERS = (AppRole.ADMIN, AppRole.DETECTION_ENGINEER)
_ANALYST_PLUS = (AppRole.ANALYST, AppRole.DETECTION_ENGINEER, AppRole.ADMIN)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SLA_SETTING = {
    "critical": "SLA_MINUTES_CRITICAL",
    "high": "SLA_MINUTES_HIGH",
    "medium": "SLA_MINUTES_MEDIUM",
    "low": "SLA_MINUTES_LOW",
}


@router.post("/ingest", response_model=ScanIngestResponse)
async def ingest_scan(
    file: UploadFile = File(...),
    scanner: str | None = Query(default=None, description="nessus | csv; auto-detected when omitted"),
    current_user: User = Depends(require_roles(*_VULN_MANAGERS)),
    db: Session = Depends(get_db),
) -> ScanIngestResponse:
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Scan file exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit",
        )
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")

    filename = file.filename or "upload"
    chosen = scanner or detect_scanner(filename, content)
    parser = PARSERS.get(chosen)
    if parser is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported scanner {chosen!r}; expected one of {sorted(PARSERS)}",
        )

    record = ScanImport(filename=filename[:512], scanner=chosen, imported_by=current_user.username)
    try:
        findings = parser(content)
    except ScanParseError as exc:
        record.status = "failed"
        record.error_message = str(exc)[:2000]
        db.add(record)
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    result = ingest_findings(db, findings, chosen)
    record.findings_imported = result.imported + result.updated
    record.findings_failed = result.failed
    record.assets_touched = result.assets_touched
    record.status = "succeeded" if result.failed == 0 else "partial"
    db.add(record)
    db.commit()
    db.refresh(record)

    append_audit_event(
        db,
        actor=current_user.username,
        action="vulnerability_scan_ingested",
        resource=f"scan_import:{record.id}",
        details={
            "filename": filename,
            "scanner": chosen,
            "imported": result.imported,
            "updated": result.updated,
            "failed": result.failed,
        },
    )

    return ScanIngestResponse(
        import_id=record.id,
        scanner=chosen,
        imported=result.imported,
        updated=result.updated,
        failed=result.failed,
        assets_touched=result.assets_touched,
        errors=result.errors,
    )


@router.get("/imports", response_model=list[ScanImportOut])
def list_imports(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[ScanImport]:
    return db.query(ScanImport).order_by(ScanImport.imported_at.desc()).limit(100).all()


@router.get("/assets", response_model=Page[AssetOut])
def list_assets(
    environment: str | None = None,
    criticality: str | None = None,
    internet_facing: bool | None = None,
    search: str | None = Query(default=None, max_length=255),
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[AssetOut]:
    query = db.query(Asset)
    if environment:
        query = query.filter(Asset.environment == environment)
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if internet_facing is not None:
        query = query.filter(Asset.internet_facing.is_(internet_facing))
    if search:
        query = query.filter(Asset.hostname.ilike(f"%{search}%"))

    rows, total = paginate(db, query.order_by(Asset.hostname.asc()), params)
    return Page[AssetOut](
        items=[AssetOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.post("/assets", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    current_user: User = Depends(require_roles(*_VULN_MANAGERS)),
    db: Session = Depends(get_db),
) -> Asset:
    existing = (
        db.query(Asset)
        .filter(Asset.hostname == payload.hostname, Asset.ip_address == payload.ip_address)
        .first()
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset already exists")
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    current_user: User = Depends(require_roles(*_VULN_MANAGERS)),
    db: Session = Depends(get_db),
) -> Asset:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    for attribute, value in payload.model_dump(exclude_unset=True, exclude_none=True).items():
        setattr(asset, attribute, value)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("", response_model=Page[VulnerabilityOut])
def list_vulnerabilities(
    severity: str | None = None,
    remediation_status: str | None = None,
    asset_id: int | None = None,
    cve_id: str | None = None,
    internet_facing: bool | None = None,
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    search: str | None = Query(default=None, max_length=255),
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[VulnerabilityOut]:
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if remediation_status:
        query = query.filter(Vulnerability.remediation_status == remediation_status)
    if asset_id is not None:
        query = query.filter(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.filter(Vulnerability.cve_id == cve_id)
    if min_cvss is not None:
        query = query.filter(Vulnerability.cvss_score >= min_cvss)
    if search:
        query = query.filter(Vulnerability.title.ilike(f"%{search}%"))
    if internet_facing is not None:
        query = query.join(Asset, Asset.id == Vulnerability.asset_id).filter(
            Asset.internet_facing.is_(internet_facing)
        )

    rows, total = paginate(
        db, query.order_by(Vulnerability.cvss_score.desc().nullslast(), Vulnerability.id.desc()), params
    )
    return Page[VulnerabilityOut](
        items=[VulnerabilityOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/{vulnerability_id}", response_model=VulnerabilityDetailOut)
def get_vulnerability(
    vulnerability_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> VulnerabilityDetailOut:
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
    return VulnerabilityDetailOut(
        **VulnerabilityOut.model_validate(vuln).model_dump(),
        asset=AssetOut.model_validate(asset),
        raw=vuln.raw or {},
    )


@router.patch("/{vulnerability_id}/status", response_model=VulnerabilityOut)
def update_remediation_status(
    vulnerability_id: int,
    payload: VulnerabilityStatusUpdate,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
) -> Vulnerability:
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")

    previous = vuln.remediation_status
    vuln.remediation_status = payload.remediation_status
    vuln.remediated_at = (
        datetime.now(timezone.utc) if payload.remediation_status == RemediationStatus.REMEDIATED else None
    )
    db.commit()
    db.refresh(vuln)

    append_audit_event(
        db,
        actor=current_user.username,
        action="vulnerability_status_changed",
        resource=f"vulnerability:{vuln.id}",
        details={"from": previous, "to": payload.remediation_status, "cve": vuln.cve_id},
    )
    return vuln


@router.post("/promote", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def promote_vulnerabilities_to_case(
    payload: VulnPromoteRequest,
    current_user: User = Depends(require_roles(*_ANALYST_PLUS)),
    db: Session = Depends(get_db),
) -> Case:
    """Mirror of alert promotion (FRD-VULN-04): a critical CVE on an
    internet-facing asset gets the same case workflow as a detection."""
    vulns = db.query(Vulnerability).filter(Vulnerability.id.in_(payload.vulnerability_ids)).all()
    if len(vulns) != len(set(payload.vulnerability_ids)):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="One or more vulnerabilities not found"
        )

    highest = max((v.severity for v in vulns), key=lambda s: _SEVERITY_RANK.get(s, 0))
    settings = get_settings()
    sla_minutes = getattr(settings, _SLA_SETTING.get(highest, "SLA_MINUTES_MEDIUM"))
    now = datetime.now(timezone.utc)

    case = Case(
        title=payload.title or f"Vulnerability remediation: {vulns[0].title}",
        severity=highest,
        status=CaseStatus.NEW,
        sla_due_at=now + timedelta(minutes=sla_minutes),
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    db.add(
        CaseTimelineEvent(
            case_id=case.id,
            type=TimelineEventType.CREATED,
            content={"promoted_from_vulnerability_ids": payload.vulnerability_ids},
            actor=current_user.username,
        )
    )
    for vuln in vulns:
        vuln.case_id = case.id
        if vuln.remediation_status == RemediationStatus.OPEN:
            vuln.remediation_status = RemediationStatus.IN_PROGRESS
        db.add(
            CaseTimelineEvent(
                case_id=case.id,
                type=TimelineEventType.VULNERABILITY_LINKED,
                content={"vulnerability_id": vuln.id, "cve_id": vuln.cve_id, "title": vuln.title},
                actor=current_user.username,
            )
        )
    db.commit()
    db.refresh(case)

    append_audit_event(
        db,
        actor=current_user.username,
        action="vulnerabilities_promoted_to_case",
        resource=f"case:{case.id}",
        details={"vulnerability_ids": payload.vulnerability_ids},
    )
    return case
