"""
Threat-intelligence models.

FRD ref: FRD-TI-01/02 — indicators of compromise (IOCs) sourced from
external feeds (MISP, OTX, a STIX/TAXII collection, or a manual analyst
upload) are stored here and matched against normalized events during
enrichment (services/enrichment.py).

`IOC.value_normalized` is the lookup key: lower-cased and whitespace-
stripped so `10.0.0.5`, ` 10.0.0.5 ` and a domain in mixed case all
collapse to a single indexed form. `(type, value_normalized)` is unique —
re-importing a feed updates confidence/last_seen instead of duplicating.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON


class IOCType:
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"

    ALL = (IP, DOMAIN, URL, FILE_HASH, EMAIL)


class ThreatIntelFeed(Base):
    """A configured source of indicators."""

    __tablename__ = "threat_intel_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # "manual" | "http_json" | "misp" | "otx" | "stix_taxii"
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    default_confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_poll_status: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_poll_indicator_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class IOC(Base):
    """A single indicator of compromise."""

    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("type", "value_normalized", name="uq_ioc_type_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    value_normalized: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)

    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    description: Mapped[str] = mapped_column(String(2000), default="")
    tags: Mapped[list] = mapped_column(PortableJSON, default=list)

    feed_id: Mapped[int | None] = mapped_column(ForeignKey("threat_intel_feeds.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(128), default="manual", nullable=False)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Denormalized hit counter maintained by services/enrichment.py.
    match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


def normalize_ioc_value(value: str) -> str:
    return value.strip().lower()
