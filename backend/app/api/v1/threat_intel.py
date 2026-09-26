"""
FRD ref: FRD-TI-01..04 — IOC inventory, bulk import, feed configuration,
and on-demand feed polling.

Writes are restricted to detection-engineer/admin: a bad indicator (say,
the corporate egress IP marked malicious) turns every outbound connection
into an alert, so indicator authorship is a privileged action and is
audited accordingly.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.ioc import IOC, ThreatIntelFeed
from app.models.user import AppRole, User
from app.schemas.threat_intel import (
    FeedCreate,
    FeedOut,
    FeedPollResult,
    IOCBulkCreate,
    IOCBulkResult,
    IOCCreate,
    IOCOut,
    IOCUpdate,
)
from app.services.audit_chain import append_audit_event
from app.services.enrichment import upsert_ioc
from app.services.threat_feeds import poll_feed

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

_TI_AUTHORS = (AppRole.DETECTION_ENGINEER, AppRole.ADMIN)


def _get_ioc_or_404(db: Session, ioc_id: int) -> IOC:
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if ioc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    return ioc


@router.get("/iocs", response_model=Page[IOCOut])
def list_iocs(
    type_filter: str | None = Query(default=None, alias="type"),
    severity: str | None = None,
    active: bool | None = None,
    source: str | None = None,
    search: str | None = Query(default=None, max_length=256),
    min_confidence: int | None = Query(default=None, ge=0, le=100),
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[IOCOut]:
    query = db.query(IOC)
    if type_filter:
        query = query.filter(IOC.type == type_filter)
    if severity:
        query = query.filter(IOC.severity == severity)
    if active is not None:
        query = query.filter(IOC.active.is_(active))
    if source:
        query = query.filter(IOC.source == source)
    if min_confidence is not None:
        query = query.filter(IOC.confidence >= min_confidence)
    if search:
        query = query.filter(IOC.value_normalized.ilike(f"%{search.strip().lower()}%"))

    rows, total = paginate(db, query.order_by(IOC.last_seen.desc()), params)
    return Page[IOCOut](
        items=[IOCOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.post("/iocs", response_model=IOCOut, status_code=status.HTTP_201_CREATED)
def create_ioc(
    payload: IOCCreate,
    current_user: User = Depends(require_roles(*_TI_AUTHORS)),
    db: Session = Depends(get_db),
) -> IOC:
    ioc, created = upsert_ioc(
        db,
        ioc_type=payload.type,
        value=payload.value,
        confidence=payload.confidence,
        severity=payload.severity,
        description=payload.description,
        tags=payload.tags,
        source=f"manual:{current_user.username}",
        expires_at=payload.expires_at,
    )
    append_audit_event(
        db,
        actor=current_user.username,
        action="ioc_created" if created else "ioc_updated",
        resource=f"ioc:{ioc.id}",
        details={"type": ioc.type, "value": ioc.value},
    )
    return ioc


@router.post("/iocs/bulk", response_model=IOCBulkResult)
def bulk_import_iocs(
    payload: IOCBulkCreate,
    current_user: User = Depends(require_roles(*_TI_AUTHORS)),
    db: Session = Depends(get_db),
) -> IOCBulkResult:
    created = updated = 0
    for indicator in payload.indicators:
        _, was_created = upsert_ioc(
            db,
            ioc_type=indicator.type,
            value=indicator.value,
            confidence=indicator.confidence,
            severity=indicator.severity,
            description=indicator.description,
            tags=indicator.tags,
            source=payload.source,
            expires_at=indicator.expires_at,
        )
        created += int(was_created)
        updated += int(not was_created)

    append_audit_event(
        db,
        actor=current_user.username,
        action="iocs_bulk_imported",
        resource="threat-intel:iocs",
        details={"created": created, "updated": updated, "source": payload.source},
    )
    return IOCBulkResult(created=created, updated=updated, total=created + updated)


@router.patch("/iocs/{ioc_id}", response_model=IOCOut)
def update_ioc(
    ioc_id: int,
    payload: IOCUpdate,
    current_user: User = Depends(require_roles(*_TI_AUTHORS)),
    db: Session = Depends(get_db),
) -> IOC:
    ioc = _get_ioc_or_404(db, ioc_id)
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    for attribute, value in changes.items():
        setattr(ioc, attribute, value)
    db.commit()
    db.refresh(ioc)

    if changes:
        append_audit_event(
            db,
            actor=current_user.username,
            action="ioc_updated",
            resource=f"ioc:{ioc.id}",
            details={k: str(v) for k, v in changes.items()},
        )
    return ioc


@router.delete("/iocs/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_ioc(
    ioc_id: int,
    current_user: User = Depends(require_roles(*_TI_AUTHORS)),
    db: Session = Depends(get_db),
) -> Response:
    """Deactivate rather than delete, so historical enrichment on past events
    still resolves to a real indicator row."""
    ioc = _get_ioc_or_404(db, ioc_id)
    ioc.active = False
    db.commit()

    append_audit_event(
        db,
        actor=current_user.username,
        action="ioc_deactivated",
        resource=f"ioc:{ioc.id}",
        details={"type": ioc.type, "value": ioc.value},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/feeds", response_model=list[FeedOut])
def list_feeds(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[ThreatIntelFeed]:
    return db.query(ThreatIntelFeed).order_by(ThreatIntelFeed.id.asc()).all()


@router.post("/feeds", response_model=FeedOut, status_code=status.HTTP_201_CREATED)
def create_feed(
    payload: FeedCreate,
    current_user: User = Depends(require_roles(*_TI_AUTHORS)),
    db: Session = Depends(get_db),
) -> ThreatIntelFeed:
    if db.query(ThreatIntelFeed).filter(ThreatIntelFeed.name == payload.name).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A feed with that name exists")
    if payload.kind != "manual" and not payload.url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"A {payload.kind} feed requires a url"
        )

    feed = ThreatIntelFeed(**payload.model_dump())
    db.add(feed)
    db.commit()
    db.refresh(feed)

    append_audit_event(
        db,
        actor=current_user.username,
        action="threat_intel_feed_created",
        resource=f"feed:{feed.id}",
        details={"name": feed.name, "kind": feed.kind},
    )
    return feed


@router.post("/feeds/{feed_id}/poll", response_model=FeedPollResult)
def poll_feed_now(
    feed_id: int,
    current_user: User = Depends(require_roles(*_TI_AUTHORS)),
    db: Session = Depends(get_db),
) -> FeedPollResult:
    """Force an immediate poll instead of waiting for the scheduler."""
    feed = db.query(ThreatIntelFeed).filter(ThreatIntelFeed.id == feed_id).first()
    if feed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")

    result = poll_feed(db, feed)
    append_audit_event(
        db,
        actor=current_user.username,
        action="threat_intel_feed_polled",
        resource=f"feed:{feed.id}",
        details={"fetched": result.fetched, "created": result.created, "error": result.error},
    )
    return FeedPollResult(
        feed_name=result.feed_name,
        fetched=result.fetched,
        created=result.created,
        updated=result.updated,
        error=result.error,
    )
