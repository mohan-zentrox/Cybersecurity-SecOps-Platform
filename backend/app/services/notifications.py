"""
Alert notification dispatch.

FRD ref: FRD-ALERT-04 — writing an Alert row is not alerting; a human has
to be told. This module fans a notification out to every enabled
`NotificationChannel` whose `min_severity` floor is met, and records one
`NotificationDelivery` row per attempt so an on-call engineer can later
prove whether a page actually went out.

Channel types
-------------
  * ``log``     — always available, writes a structured log line. Used as
                  the default channel so a fresh install still shows that
                  alerting fired, with no external dependency.
  * ``webhook`` — HTTP POST of the JSON payload to ``config["url"]``.
  * ``slack``   — HTTP POST of a Slack incoming-webhook message body.
  * ``email``   — SMTP send via the SMTP_* settings.

Dispatch is best-effort and never raises into the caller: a detection
pipeline must not fail to record an alert because Slack was down. Failures
are captured on the delivery row with ``status="failed"``.
"""

import json
import logging
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.notification import ChannelType, DeliveryStatus, NotificationChannel, NotificationDelivery

log = logging.getLogger("aegis.notifications")

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Notification:
    """A rendered, channel-agnostic message."""

    subject_type: str  # "alert" | "sla_breach" | "test"
    subject_id: int | None
    severity: str
    title: str
    body: str
    fields: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "severity": self.severity,
            "title": self.title,
            "body": self.body,
            "fields": self.fields,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }


def severity_meets(severity: str, floor: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(floor, 0)


# --------------------------------------------------------------------------
# Transports. Each returns a short human-readable detail string on success
# and raises on failure; the caller turns exceptions into failed deliveries.
# --------------------------------------------------------------------------


ALLOWED_URL_SCHEMES = ("http", "https")


def require_http_url(url: str, *, what: str) -> str:
    """Reject non-HTTP(S) destinations.

    urlopen also speaks file:, ftp: and data:. A channel configured with
    ``file:///etc/passwd`` would otherwise turn an alert dispatch into a local
    file read, so the scheme is checked before the URL is ever opened.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError(f"{what} must be an http(s) URL, got scheme {parsed.scheme or 'none'!r}")
    if not parsed.netloc:
        raise ValueError(f"{what} is missing a host")
    return url


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> str:
    require_http_url(url, what="webhook URL")
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    # require_http_url() above restricts the scheme to http/https.
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
        return f"HTTP {response.status}"


def _send_log(notification: Notification, _config: dict[str, Any]) -> str:
    log.warning(
        notification.title,
        extra={
            "event.kind": "alert",
            "event.severity": notification.severity,
            "aegis.subject_type": notification.subject_type,
            "aegis.subject_id": notification.subject_id,
            "aegis.body": notification.body,
        },
    )
    return "written to structured log"


def _send_webhook(notification: Notification, config: dict[str, Any]) -> str:
    settings = get_settings()
    url = config.get("url") or settings.NOTIFY_WEBHOOK_URL
    if not url:
        raise ValueError("webhook channel has no 'url' configured")
    return _post_json(url, notification.as_payload(), settings.NOTIFY_HTTP_TIMEOUT_SECONDS)


def _send_slack(notification: Notification, config: dict[str, Any]) -> str:
    settings = get_settings()
    url = config.get("url") or settings.NOTIFY_SLACK_WEBHOOK_URL
    if not url:
        raise ValueError("slack channel has no 'url' configured")
    emoji = {"critical": ":rotating_light:", "high": ":warning:", "medium": ":large_orange_diamond:"}.get(
        notification.severity, ":white_circle:"
    )
    lines = [f"{emoji} *{notification.title}*", notification.body]
    lines += [f"• *{k}*: {v}" for k, v in notification.fields.items()]
    return _post_json(url, {"text": "\n".join(lines)}, settings.NOTIFY_HTTP_TIMEOUT_SECONDS)


def _send_email(notification: Notification, config: dict[str, Any]) -> str:
    settings = get_settings()
    recipients = config.get("to") or [r.strip() for r in settings.SMTP_TO.split(",") if r.strip()]
    if not settings.SMTP_HOST or not recipients:
        raise ValueError("email channel requires SMTP_HOST and at least one recipient")

    message = EmailMessage()
    message["Subject"] = f"[Aegis][{notification.severity.upper()}] {notification.title}"
    message["From"] = settings.SMTP_FROM
    message["To"] = ", ".join(recipients)
    detail = "\n".join(f"{k}: {v}" for k, v in notification.fields.items())
    message.set_content(f"{notification.body}\n\n{detail}")

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=settings.NOTIFY_HTTP_TIMEOUT_SECONDS) as smtp:
        if settings.SMTP_USE_TLS:
            smtp.starttls()
        if settings.SMTP_USERNAME:
            smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        smtp.send_message(message)
    return f"sent to {len(recipients)} recipient(s)"


_TRANSPORTS = {
    ChannelType.LOG: _send_log,
    ChannelType.WEBHOOK: _send_webhook,
    ChannelType.SLACK: _send_slack,
    ChannelType.EMAIL: _send_email,
}


def dispatch(db: Session, notification: Notification) -> list[NotificationDelivery]:
    """Send `notification` to every eligible channel. Never raises."""
    settings = get_settings()
    deliveries: list[NotificationDelivery] = []

    if not settings.NOTIFICATIONS_ENABLED:
        return deliveries

    channels = db.query(NotificationChannel).filter(NotificationChannel.enabled.is_(True)).all()
    for channel in channels:
        if not severity_meets(notification.severity, channel.min_severity):
            deliveries.append(
                _record(db, channel, notification, DeliveryStatus.SKIPPED, "below channel min_severity")
            )
            continue

        transport = _TRANSPORTS.get(channel.type)
        if transport is None:
            deliveries.append(
                _record(db, channel, notification, DeliveryStatus.FAILED, f"unknown channel type {channel.type!r}")
            )
            continue

        try:
            detail = transport(notification, channel.config or {})
            deliveries.append(_record(db, channel, notification, DeliveryStatus.SENT, detail))
        except (urllib.error.URLError, OSError, ValueError, smtplib.SMTPException) as exc:
            log.error(
                "notification delivery failed",
                extra={"aegis.channel": channel.name, "error.message": str(exc)},
            )
            deliveries.append(_record(db, channel, notification, DeliveryStatus.FAILED, str(exc)[:2000]))

    return deliveries


def _record(
    db: Session,
    channel: NotificationChannel,
    notification: Notification,
    status: str,
    detail: str,
) -> NotificationDelivery:
    row = NotificationDelivery(
        channel_id=channel.id,
        channel_name=channel.name,
        channel_type=channel.type,
        subject_type=notification.subject_type,
        subject_id=notification.subject_id,
        status=status,
        detail=detail,
        payload=notification.as_payload(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def notification_for_alert(alert, rule_name: str | None = None) -> Notification:
    """Build the standard notification body for a newly-raised alert."""
    fields: dict[str, Any] = {
        "Alert ID": alert.id,
        "Severity": alert.severity,
        "Rule": rule_name or f"rule:{alert.rule_id}",
        "Matched events": len(alert.matched_event_ids or []),
    }
    if alert.sla_due_at:
        fields["SLA due"] = alert.sla_due_at.isoformat()
    indicators = (alert.enrichment or {}).get("indicators") or []
    if indicators:
        fields["Threat intel"] = ", ".join(str(i.get("value")) for i in indicators[:5])
    return Notification(
        subject_type="alert",
        subject_id=alert.id,
        severity=alert.severity,
        title=alert.title,
        body=f"A {alert.severity} severity detection fired and is awaiting triage.",
        fields=fields,
    )


def notification_for_sla_breach(subject_type: str, subject_id: int, title: str, severity: str, due_at) -> Notification:
    return Notification(
        subject_type="sla_breach",
        subject_id=subject_id,
        severity=severity,
        title=f"SLA breached: {title}",
        body=f"The response SLA for {subject_type} {subject_id} has elapsed without closure.",
        fields={"Due at": due_at.isoformat() if due_at else "unknown", "Severity": severity},
    )
