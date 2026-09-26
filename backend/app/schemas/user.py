from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

Role = Literal["analyst", "detection-engineer", "compliance", "admin"]

# bcrypt hashes at most 72 bytes; app.core.security rejects longer inputs, so
# cap here too rather than letting the request reach the hasher and 500.
PASSWORD_MIN = 12
PASSWORD_MAX = 72


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)
    role: Role = "analyst"
    is_active: bool = True


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: Role | None = None
    is_active: bool | None = None


class PasswordChange(BaseModel):
    """Self-service password change; requires the caller's current password."""

    current_password: str
    new_password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)


class PasswordReset(BaseModel):
    """Admin-driven reset; does not require the target's current password."""

    new_password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)
