"""
FRD ref: FRD-KPI-01/02 — SOC operational metrics.

Returns pre-aggregated series so the console renders directly from the
response and no row-level data leaves the server. Also exposes a manual
SLA sweep so an operator can force breach evaluation rather than waiting
for the scheduler tick.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_roles
from app.models.user import AppRole, User
from app.schemas.kpi import KPISummary
from app.services.kpi import kpi_summary
from app.services.sla import sweep_sla_breaches

router = APIRouter(prefix="/kpis", tags=["kpis"])


@router.get("/summary", response_model=KPISummary)
def get_kpi_summary(
    window: str = Query(default="7d", description="Reporting window, e.g. 24h, 7d, 30d"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return kpi_summary(db, window)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/sla-sweep")
def run_sla_sweep(
    current_user: User = Depends(require_roles(AppRole.ADMIN, AppRole.ANALYST)),
    db: Session = Depends(get_db),
) -> dict:
    """Force an immediate SLA breach evaluation (normally run on a timer)."""
    result = sweep_sla_breaches(db)
    return {
        "alerts_breached": result.alerts_breached,
        "cases_breached": result.cases_breached,
        "total": result.total,
    }
