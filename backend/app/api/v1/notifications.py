"""
FRD ref: FRD-ALERT-04 — notification channel configuration, delivery
history, and a test-send so an operator can prove a channel works before
relying on it during an incident.

Channel configuration is admin-only: a channel config holds a webhook URL,
which is a credential-equivalent (anyone holding it can post into the
destination channel).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.models.notification import ChannelType, NotificationChannel, NotificationDelivery
from app.models.user import AppRole, User
from app.schemas.notification import (
    ChannelCreate,
    ChannelOut,
    ChannelTestResult,
    ChannelUpdate,
    DeliveryOut,
)
from app.services.audit_chain import append_audit_event
from app.services.notifications import Notification, _TRANSPORTS

router = APIRouter(prefix="/notifications", tags=["notifications"])

_CHANNEL_ADMINS = (AppRole.ADMIN,)


def _get_channel_or_404(db: Session, channel_id: int) -> NotificationChannel:
    channel = db.query(NotificationChannel).filter(NotificationChannel.id == channel_id).first()
    if channel is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")
    return channel


@router.get("/channels", response_model=list[ChannelOut])
def list_channels(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[NotificationChannel]:
    return db.query(NotificationChannel).order_by(NotificationChannel.id.asc()).all()


@router.post("/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED)
def create_channel(
    payload: ChannelCreate,
    current_user: User = Depends(require_roles(*_CHANNEL_ADMINS)),
    db: Session = Depends(get_db),
) -> NotificationChannel:
    if db.query(NotificationChannel).filter(NotificationChannel.name == payload.name).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A channel with that name exists")
    if payload.type in (ChannelType.WEBHOOK, ChannelType.SLACK) and not payload.config.get("url"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A {payload.type} channel requires config.url",
        )

    channel = NotificationChannel(**payload.model_dump())
    db.add(channel)
    db.commit()
    db.refresh(channel)

    append_audit_event(
        db,
        actor=current_user.username,
        action="notification_channel_created",
        resource=f"notification_channel:{channel.id}",
        details={"name": channel.name, "type": channel.type},
    )
    return channel


@router.patch("/channels/{channel_id}", response_model=ChannelOut)
def update_channel(
    channel_id: int,
    payload: ChannelUpdate,
    current_user: User = Depends(require_roles(*_CHANNEL_ADMINS)),
    db: Session = Depends(get_db),
) -> NotificationChannel:
    channel = _get_channel_or_404(db, channel_id)
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    for attribute, value in changes.items():
        setattr(channel, attribute, value)
    db.commit()
    db.refresh(channel)

    if changes:
        append_audit_event(
            db,
            actor=current_user.username,
            action="notification_channel_updated",
            resource=f"notification_channel:{channel.id}",
            # Never echo config back into the audit log — it holds webhook URLs.
            details={"fields": sorted(changes)},
        )
    return channel


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_channel(
    channel_id: int,
    current_user: User = Depends(require_roles(*_CHANNEL_ADMINS)),
    db: Session = Depends(get_db),
) -> Response:
    channel = _get_channel_or_404(db, channel_id)
    name = channel.name
    db.delete(channel)
    db.commit()

    append_audit_event(
        db,
        actor=current_user.username,
        action="notification_channel_deleted",
        resource=f"notification_channel:{channel_id}",
        details={"name": name},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/channels/{channel_id}/test", response_model=ChannelTestResult)
def test_channel(
    channel_id: int,
    current_user: User = Depends(require_roles(*_CHANNEL_ADMINS)),
    db: Session = Depends(get_db),
) -> ChannelTestResult:
    """Send a test message through one channel and record the outcome."""
    channel = _get_channel_or_404(db, channel_id)
    transport = _TRANSPORTS.get(channel.type)
    if transport is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown channel type {channel.type!r}"
        )

    notification = Notification(
        subject_type="test",
        subject_id=None,
        severity="critical",  # bypass every min_severity floor
        title="Project Aegis test notification",
        body=f"Test dispatch requested by {current_user.username}.",
        fields={"channel": channel.name},
    )
    try:
        detail = transport(notification, channel.config or {})
        result = ChannelTestResult(channel_name=channel.name, status="sent", detail=detail)
    except Exception as exc:  # noqa: BLE001 - a failing test send is a reportable result, not a 500
        result = ChannelTestResult(channel_name=channel.name, status="failed", detail=str(exc)[:2000])

    db.add(
        NotificationDelivery(
            channel_id=channel.id,
            channel_name=channel.name,
            channel_type=channel.type,
            subject_type="test",
            subject_id=None,
            status=result.status,
            detail=result.detail,
            payload=notification.as_payload(),
        )
    )
    db.commit()
    return result


@router.get("/deliveries", response_model=Page[DeliveryOut])
def list_deliveries(
    status_filter: str | None = Query(default=None, alias="status"),
    subject_type: str | None = None,
    channel_id: int | None = None,
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[DeliveryOut]:
    """Delivery audit trail — proof of whether a page actually went out."""
    query = db.query(NotificationDelivery)
    if status_filter:
        query = query.filter(NotificationDelivery.status == status_filter)
    if subject_type:
        query = query.filter(NotificationDelivery.subject_type == subject_type)
    if channel_id is not None:
        query = query.filter(NotificationDelivery.channel_id == channel_id)

    rows, total = paginate(db, query.order_by(NotificationDelivery.attempted_at.desc()), params)
    return Page[DeliveryOut](
        items=[DeliveryOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )
