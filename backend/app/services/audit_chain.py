"""
Tamper-evident hash chain for the audit log.

FRD ref: FRD-AUDIT-01/02.

Each AuditEvent row's `content_hash` commits to: its own fields AND the
`prev_hash` field, which in turn equals the previous row's `content_hash`.
This is the same construction used by append-only ledgers/blockchains: to
alter or delete a historical row without detection, an attacker would need
to recompute the hash of every subsequent row.

`verify_chain` walks the table in primary-key order and independently
recomputes each row's expected content hash, reporting the id of the
first row where either:
  (a) the stored prev_hash does not equal the previous row's content_hash
      (a row was inserted/deleted/reordered), or
  (b) the recomputed content hash does not match the stored content_hash
      (a row's fields were edited in place).
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.audit import GENESIS_HASH, AuditEvent


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))


def _normalize_timestamp(ts: datetime) -> str:
    """Coerce a datetime to a canonical UTC ISO-8601 string.

    SQLite (used in tests) does not persist tzinfo on DateTime columns, so a
    row read back from the DB yields a naive datetime even though every
    timestamp we ever write is UTC. We treat naive datetimes as UTC so hash
    recomputation is stable across the write -> commit -> re-read cycle on
    both SQLite and PostgreSQL.
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def compute_content_hash(
    *, prev_hash: str, timestamp: datetime, actor: str, action: str, resource: str, details: dict
) -> str:
    payload = _canonical_json(
        {
            "prev_hash": prev_hash,
            "timestamp": _normalize_timestamp(timestamp),
            "actor": actor,
            "action": action,
            "resource": resource,
            "details": details or {},
        }
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit_event(
    db: Session, *, actor: str, action: str, resource: str, details: dict | None = None
) -> AuditEvent:
    """Append a new tamper-evident audit row. Call this for every privileged action."""
    details = details or {}
    last = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    prev_hash = last.content_hash if last is not None else GENESIS_HASH
    timestamp = datetime.now(timezone.utc)

    content_hash = compute_content_hash(
        prev_hash=prev_hash,
        timestamp=timestamp,
        actor=actor,
        action=action,
        resource=resource,
        details=details,
    )

    row = AuditEvent(
        timestamp=timestamp,
        actor=actor,
        action=action,
        resource=resource,
        details=details,
        prev_hash=prev_hash,
        content_hash=content_hash,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@dataclass
class ChainVerificationResult:
    intact: bool
    total_events: int
    first_broken_event_id: int | None = None
    reason: str | None = None


def verify_chain(db: Session) -> ChainVerificationResult:
    rows = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()

    expected_prev = GENESIS_HASH
    for row in rows:
        if row.prev_hash != expected_prev:
            return ChainVerificationResult(
                intact=False,
                total_events=len(rows),
                first_broken_event_id=row.id,
                reason=(
                    f"audit_events.id={row.id}: prev_hash does not match the previous "
                    "row's content_hash (a row was likely inserted, deleted, or reordered)"
                ),
            )

        recomputed = compute_content_hash(
            prev_hash=row.prev_hash,
            timestamp=row.timestamp,
            actor=row.actor,
            action=row.action,
            resource=row.resource,
            details=row.details,
        )
        if recomputed != row.content_hash:
            return ChainVerificationResult(
                intact=False,
                total_events=len(rows),
                first_broken_event_id=row.id,
                reason=f"audit_events.id={row.id}: content_hash mismatch (row content was modified)",
            )

        expected_prev = row.content_hash

    return ChainVerificationResult(intact=True, total_events=len(rows))
