"""
FRD ref: FRD-COMP-01..03 — control catalogue, report generation, and
report download.

Generation is synchronous here because every evidence collector is an
aggregate query over local tables and completes in milliseconds. The
`status` field on the report row already models an async lifecycle
(pending -> running -> completed/failed), so moving generation onto the
queue later changes the route body and nothing else.
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.compliance import ComplianceControl, ComplianceReport, Framework, ReportStatus
from app.models.user import AppRole, User
from app.schemas.compliance import ControlOut, ReportCreate, ReportDetailOut, ReportOut
from app.services.audit_chain import append_audit_event
from app.services.compliance import generate_report, seed_default_controls

router = APIRouter(prefix="/compliance", tags=["compliance"])

_COMPLIANCE_READERS = (AppRole.COMPLIANCE, AppRole.ADMIN)

MAX_REPORT_PERIOD_DAYS = 400


@router.get("/controls", response_model=list[ControlOut])
def list_controls(
    framework: str | None = Query(default=None),
    current_user: User = Depends(require_roles(*_COMPLIANCE_READERS)),
    db: Session = Depends(get_db),
) -> list[ComplianceControl]:
    query = db.query(ComplianceControl)
    if framework:
        query = query.filter(ComplianceControl.framework == framework)
    return query.order_by(ComplianceControl.framework.asc(), ComplianceControl.control_id.asc()).all()


@router.post("/controls/seed", response_model=list[ControlOut])
def seed_controls(
    current_user: User = Depends(require_roles(AppRole.ADMIN)),
    db: Session = Depends(get_db),
) -> list[ComplianceControl]:
    """Install the built-in SOC2 / ISO27001 / PCI-DSS control catalogue. Idempotent."""
    added = seed_default_controls(db)
    append_audit_event(
        db,
        actor=current_user.username,
        action="compliance_controls_seeded",
        resource="compliance:controls",
        details={"added": added},
    )
    return db.query(ComplianceControl).order_by(ComplianceControl.framework.asc()).all()


@router.get("/frameworks", response_model=list[str])
def list_frameworks(
    current_user: User = Depends(require_roles(*_COMPLIANCE_READERS)),
) -> list[str]:
    return list(Framework.ALL)


@router.get("/reports", response_model=Page[ReportOut])
def list_reports(
    framework: str | None = None,
    params: PageParams = Depends(page_params),
    current_user: User = Depends(require_roles(*_COMPLIANCE_READERS)),
    db: Session = Depends(get_db),
) -> Page[ReportOut]:
    query = db.query(ComplianceReport)
    if framework:
        query = query.filter(ComplianceReport.framework == framework)
    rows, total = paginate(db, query.order_by(ComplianceReport.created_at.desc()), params)
    return Page[ReportOut](
        items=[ReportOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.post("/reports", response_model=ReportDetailOut, status_code=status.HTTP_201_CREATED)
def create_report(
    payload: ReportCreate,
    current_user: User = Depends(require_roles(*_COMPLIANCE_READERS)),
    db: Session = Depends(get_db),
) -> ComplianceReport:
    if payload.period_end <= payload.period_start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="period_end must be after period_start"
        )
    if (payload.period_end - payload.period_start) > timedelta(days=MAX_REPORT_PERIOD_DAYS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Reporting period may not exceed {MAX_REPORT_PERIOD_DAYS} days",
        )

    # Auto-install the catalogue on first use so a fresh deployment can
    # generate a report without a separate seeding step.
    seed_default_controls(db)

    report = generate_report(
        db,
        framework=payload.framework,
        period_start=payload.period_start,
        period_end=payload.period_end,
        generated_by=current_user.username,
    )

    append_audit_event(
        db,
        actor=current_user.username,
        action="compliance_report_generated",
        resource=f"compliance_report:{report.id}",
        details={
            "framework": report.framework,
            "status": report.status,
            "passed": report.controls_passed,
            "failed": report.controls_failed,
        },
    )
    if report.status == ReportStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=report.error_message or "Report generation failed",
        )
    return report


@router.get("/reports/{report_id}", response_model=ReportDetailOut)
def get_report(
    report_id: int,
    current_user: User = Depends(require_roles(*_COMPLIANCE_READERS)),
    db: Session = Depends(get_db),
) -> ComplianceReport:
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("/reports/{report_id}/download", response_class=HTMLResponse)
def download_report(
    report_id: int,
    current_user: User = Depends(require_roles(*_COMPLIANCE_READERS)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Download the rendered artifact. Self-contained HTML — print to PDF from
    any browser, which avoids a native PDF toolchain in the container image."""
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    if not report.rendered_html:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Report has no rendered artifact"
        )

    filename = f"aegis-{report.framework.lower()}-{report.id}.html"
    return HTMLResponse(
        content=report.rendered_html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
