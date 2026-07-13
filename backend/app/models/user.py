"""
FRD ref: FRD-AUTH-01/03 — user identity and RBAC role.

Role values are deliberately a plain string column (not a DB-native enum)
so new roles can be added via application-level constants without an
Alembic migration. Valid values are enforced at the Pydantic schema layer
(see app/schemas/user.py) and re-checked by the role-gated dependency in
app/core/deps.py.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AppRole:
    ANALYST = "analyst"
    DETECTION_ENGINEER = "detection-engineer"
    COMPLIANCE = "compliance"
    ADMIN = "admin"

    ALL = (ANALYST, DETECTION_ENGINEER, COMPLIANCE, ADMIN)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default=AppRole.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
