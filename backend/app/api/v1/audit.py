"""
FRD ref: FRD-AUDIT-01/02/03 — paged, filterable read access to the
hash-chained audit log, a verification endpoint that walks the chain and
reports tamper status, and a CSV export for auditors.

Restricted to compliance/admin roles since the audit log itself is
sensitive: it reveals every privileged action across the platform.
"""

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.audit import AuditEvent
from app.models.user import AppRole, User
from app.schemas.audit import AuditEventOut, AuditVerifyResponse
from app.services.audit_chain import verify_chain

router = APIRouter(prefix="/audit", tags=["audit"])

_AUDIT_READERS = (AppRole.COMPLIANCE, AppRole.ADMIN)

EXPORT_MAX_ROWS = 100_000


def _filtered(db: Session, actor: str | None, action: str | None, resource: str | None,
              since: datetime | None, until: datetime | None):
    query = db.query(AuditEvent)
    if actor:
        query = query.filter(AuditEvent.actor == actor)
    if action:
        query = query.filter(AuditEvent.action == action)
    if resource:
        query = query.filter(AuditEvent.resource.ilike(f"%{resource}%"))
    if since:
        query = query.filter(AuditEvent.timestamp >= since)
    if until:
        query = query.filter(AuditEvent.timestamp <= until)
    return query


@router.get("", response_model=Page[AuditEventOut])
def list_audit_events(
    actor: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    params: PageParams = Depends(page_params),
    current_user: User = Depends(require_roles(*_AUDIT_READERS)),
    db: Session = Depends(get_db),
) -> Page[AuditEventOut]:
    query = _filtered(db, actor, action, resource, since, until)
    rows, total = paginate(db, query.order_by(AuditEvent.id.desc()), params)
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


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


@router.get("/actions", response_model=list[str])
def list_audit_actions(
    current_user: User = Depends(require_roles(*_AUDIT_READERS)), db: Session = Depends(get_db)
) -> list[str]:
    """Distinct action names, for populating the console filter dropdown."""
    return sorted(a for (a,) in db.query(AuditEvent.action).distinct().all())


@router.get("/export")
def export_audit_csv(
    actor: str | None = None,
    action: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=10_000, ge=1, le=EXPORT_MAX_ROWS),
    current_user: User = Depends(require_roles(*_AUDIT_READERS)),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """CSV export including the chain hashes, so an auditor can re-verify the
    chain offline with the same construction the API uses."""
    rows = (
        _filtered(db, actor, action, None, since, until)
        .order_by(AuditEvent.id.asc())
        .limit(limit)
        .all()
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "timestamp", "actor", "action", "resource", "details", "prev_hash", "content_hash"])
    for row in rows:
        writer.writerow(
            [
                row.id,
                row.timestamp.isoformat(),
                row.actor,
                row.action,
                row.resource,
                row.details,
                row.prev_hash,
                row.content_hash,
            ]
        )
    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="aegis-audit-log.csv"'},
    )
