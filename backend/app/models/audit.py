"""
Tamper-evident, hash-chained audit log.

FRD ref: FRD-AUDIT-01/02 — every privileged action (login, rule mutation,
alert/case status transition, audit access) must be recorded so that any
retroactive edit or deletion of a row is detectable. Each row commits to
the content hash of the row immediately before it, forming a Merkle-style
chain analogous to a blockchain ledger. See services/audit_chain.py for
the hashing/append/verify logic — the model here is intentionally "dumb"
(no hashing logic lives on the ORM class) so the chain math has a single
source of truth that is easy to unit test in isolation.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, PortableJSON

GENESIS_HASH = "0" * 64


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict] = mapped_column(PortableJSON, default=dict)

    # Chain-of-custody fields
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
