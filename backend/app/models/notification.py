"""
Notification channel and delivery-attempt models.

FRD ref: FRD-ALERT-04 — raising an Alert row is not "alerting" unless a
human is told. A `NotificationChannel` is a configured destination
(webhook, Slack incoming webhook, SMTP), optionally filtered by minimum
severity. Every dispatch attempt is recorded as a `NotificationDelivery`
so an on-call engineer can prove whether a page actually went out, and so
failed deliveries can be retried.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON


class ChannelType:
    WEBHOOK = "webhook"
    SLACK = "slack"
    EMAIL = "email"
    LOG = "log"  # always-available sink; writes a structured log line

    ALL = (WEBHOOK, SLACK, EMAIL, LOG)


class DeliveryStatus:
    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    min_severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)

    # Type-specific settings: {"url": ...} for webhook/slack, {"to": [...]} for email.
    config: Mapped[dict] = mapped_column(PortableJSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    channel_name: Mapped[str] = mapped_column(String(128), nullable=False)
    channel_type: Mapped[str] = mapped_column(String(16), nullable=False)

    # What triggered this: "alert" | "sla_breach" | "test"
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    detail: Mapped[str] = mapped_column(String(2000), default="")
    payload: Mapped[dict] = mapped_column(PortableJSON, default=dict)

    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
