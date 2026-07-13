"""
FRD ref: FRD-AUDIT-01/02 — read access to the hash-chained audit log and a
verification endpoint that walks the chain and reports tamper status.
Restricted to compliance/admin roles since the audit log itself is
sensitive (it reveals every privileged action across the platform).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_roles
from app.models.audit import AuditEvent
from app.models.user import AppRole, User
from app.schemas.audit import AuditEventOut, AuditVerifyResponse
from app.services.audit_chain import verify_chain

router = APIRouter(prefix="/audit", tags=["audit"])

_AUDIT_READERS = (AppRole.COMPLIANCE, AppRole.ADMIN)


@router.get("", response_model=list[AuditEventOut])
def list_audit_events(
    current_user: User = Depends(require_roles(*_AUDIT_READERS)), db: Session = Depends(get_db)
) -> list[AuditEvent]:
    return db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()


@router.get("/verify", response_model=AuditVerifyResponse)
def verify_audit_chain(
    current_user: User = Depends(require_roles(*_AUDIT_READERS)), db: Session = Depends(get_db)
) -> AuditVerifyResponse:
    result = verify_chain(db)
    return AuditVerifyResponse(
        intact=result.intact,
        total_events=result.total_events,
        first_broken_event_id=result.first_broken_event_id,
        reason=result.reason,
    )
