"""
Threat-intel feed pollers.

FRD ref: FRD-TI-02 — feeds sit behind a `ThreatIntelFeedClient` interface,
mirroring the repository-pattern approach used for the event store, so a
new feed type is an added class rather than an edit to the polling loop.

Implemented clients:
  * ``manual``    — no-op; the feed exists only to group analyst-uploaded IOCs.
  * ``http_json`` — GETs a JSON document and reads indicators out of it.
                    Accepts either a bare list or ``{"indicators": [...]}``,
                    with per-item keys ``type``/``value``/``confidence``/
                    ``severity``/``tags``/``description``.
  * ``otx``       — AlienVault OTX pulse-indicator JSON shape.
  * ``misp``      — MISP ``/attributes/restSearch`` response shape.

Every client returns a plain list of `FeedIndicator`, so `poll_feed` can
upsert them uniformly through services/enrichment.py::upsert_ioc.
"""

import json
import logging
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.ioc import IOCType, ThreatIntelFeed
from app.services.enrichment import upsert_ioc
from app.services.notifications import require_http_url

log = logging.getLogger("aegis.threat_feeds")

# MISP/OTX indicator type names -> our canonical IOCType.
_TYPE_ALIASES: dict[str, str] = {
    "ip": IOCType.IP,
    "ipv4": IOCType.IP,
    "ipv6": IOCType.IP,
    "ip-src": IOCType.IP,
    "ip-dst": IOCType.IP,
    "ipv4-addr": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "domain-name": IOCType.DOMAIN,
    "url": IOCType.URL,
    "uri": IOCType.URL,
    "md5": IOCType.FILE_HASH,
    "sha1": IOCType.FILE_HASH,
    "sha256": IOCType.FILE_HASH,
    "filehash-md5": IOCType.FILE_HASH,
    "filehash-sha1": IOCType.FILE_HASH,
    "filehash-sha256": IOCType.FILE_HASH,
    "file_hash": IOCType.FILE_HASH,
    "email": IOCType.EMAIL,
    "email-src": IOCType.EMAIL,
}


def canonical_type(raw_type: str | None) -> str | None:
    if not raw_type:
        return None
    return _TYPE_ALIASES.get(str(raw_type).strip().lower())


@dataclass
class FeedIndicator:
    type: str
    value: str
    confidence: int = 50
    severity: str = "medium"
    description: str = ""
    tags: list[str] = field(default_factory=list)


class FeedError(Exception):
    pass


class ThreatIntelFeedClient(ABC):
    """Swap-in interface for an external indicator source."""

    def __init__(self, feed: ThreatIntelFeed):
        self.feed = feed

    @abstractmethod
    def fetch(self) -> list[FeedIndicator]: ...

    def _get_json(self) -> Any:
        if not self.feed.url:
            raise FeedError(f"feed {self.feed.name!r} has no URL configured")
        settings = get_settings()
        try:
            # Reject file:/ftp:/data: feed URLs before opening them.
            require_http_url(self.feed.url, what=f"feed {self.feed.name!r} URL")
        except ValueError as exc:
            raise FeedError(str(exc)) from exc

        request = urllib.request.Request(
            self.feed.url, headers={"Accept": "application/json", "User-Agent": "ProjectAegis/1.0"}
        )
        try:
            # require_http_url() above restricts the scheme to http/https.
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                request, timeout=settings.NOTIFY_HTTP_TIMEOUT_SECONDS * 4
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise FeedError(f"failed to fetch {self.feed.name!r}: {exc}") from exc


class ManualFeedClient(ThreatIntelFeedClient):
    """A bucket for analyst-uploaded indicators; polling is a no-op."""

    def fetch(self) -> list[FeedIndicator]:
        return []


class HttpJsonFeedClient(ThreatIntelFeedClient):
    def fetch(self) -> list[FeedIndicator]:
        document = self._get_json()
        items = document.get("indicators", []) if isinstance(document, dict) else document
        if not isinstance(items, list):
            raise FeedError("expected a JSON list or an object with an 'indicators' list")

        indicators = []
        for item in items:
            if not isinstance(item, dict):
                continue
            ioc_type = canonical_type(item.get("type"))
            value = item.get("value") or item.get("indicator")
            if not ioc_type or not value:
                continue
            indicators.append(
                FeedIndicator(
                    type=ioc_type,
                    value=str(value),
                    confidence=int(item.get("confidence", self.feed.default_confidence)),
                    severity=str(item.get("severity", "medium")),
                    description=str(item.get("description", ""))[:2000],
                    tags=[str(t) for t in (item.get("tags") or [])],
                )
            )
        return indicators


class OtxFeedClient(ThreatIntelFeedClient):
    """AlienVault OTX: {"results": [{"indicator": ..., "type": ...}, ...]}."""

    def fetch(self) -> list[FeedIndicator]:
        document = self._get_json()
        results = document.get("results", []) if isinstance(document, dict) else []
        indicators = []
        for item in results:
            ioc_type = canonical_type(item.get("type"))
            value = item.get("indicator")
            if not ioc_type or not value:
                continue
            indicators.append(
                FeedIndicator(
                    type=ioc_type,
                    value=str(value),
                    confidence=self.feed.default_confidence,
                    severity="high",
                    description=str(item.get("description") or "")[:2000],
                    tags=["otx"],
                )
            )
        return indicators


class MispFeedClient(ThreatIntelFeedClient):
    """MISP restSearch: {"response": {"Attribute": [{"type": ..., "value": ...}]}}."""

    def fetch(self) -> list[FeedIndicator]:
        document = self._get_json()
        attributes = (document or {}).get("response", {}).get("Attribute", [])
        indicators = []
        for item in attributes:
            ioc_type = canonical_type(item.get("type"))
            value = item.get("value")
            if not ioc_type or not value:
                continue
            indicators.append(
                FeedIndicator(
                    type=ioc_type,
                    value=str(value),
                    confidence=self.feed.default_confidence,
                    severity="high" if item.get("to_ids") else "medium",
                    description=str(item.get("comment") or "")[:2000],
                    tags=["misp"],
                )
            )
        return indicators


_CLIENTS: dict[str, type[ThreatIntelFeedClient]] = {
    "manual": ManualFeedClient,
    "http_json": HttpJsonFeedClient,
    "otx": OtxFeedClient,
    "misp": MispFeedClient,
}


def client_for(feed: ThreatIntelFeed) -> ThreatIntelFeedClient:
    cls = _CLIENTS.get(feed.kind)
    if cls is None:
        raise FeedError(f"unsupported feed kind {feed.kind!r}")
    return cls(feed)


@dataclass
class PollResult:
    feed_name: str
    fetched: int = 0
    created: int = 0
    updated: int = 0
    error: str | None = None


def poll_feed(db: Session, feed: ThreatIntelFeed) -> PollResult:
    """Fetch one feed and upsert its indicators. Never raises."""
    result = PollResult(feed_name=feed.name)
    try:
        indicators = client_for(feed).fetch()
    except FeedError as exc:
        result.error = str(exc)
        feed.last_polled_at = datetime.now(timezone.utc)
        feed.last_poll_status = f"error: {exc}"[:512]
        db.commit()
        log.error("threat intel feed poll failed", extra={"aegis.feed": feed.name, "error.message": str(exc)})
        return result

    result.fetched = len(indicators)
    for indicator in indicators:
        _, created = upsert_ioc(
            db,
            ioc_type=indicator.type,
            value=indicator.value,
            confidence=indicator.confidence,
            severity=indicator.severity,
            description=indicator.description,
            tags=indicator.tags,
            source=feed.name,
            feed_id=feed.id,
        )
        if created:
            result.created += 1
        else:
            result.updated += 1

    feed.last_polled_at = datetime.now(timezone.utc)
    feed.last_poll_status = f"ok: {result.created} new, {result.updated} updated"
    feed.last_poll_indicator_count = result.fetched
    db.commit()
    return result


def poll_all_enabled_feeds(db: Session) -> list[PollResult]:
    feeds = db.query(ThreatIntelFeed).filter(ThreatIntelFeed.enabled.is_(True)).all()
    return [poll_feed(db, feed) for feed in feeds if feed.kind != "manual"]
