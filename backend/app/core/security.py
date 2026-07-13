"""
Password hashing and JWT session-token helpers.

FRD ref: FRD-AUTH-01 (credential storage), FRD-AUTH-02 (session tokens).
Sessions are implemented as short-lived signed JWTs returned from
POST /api/v1/auth/login. The server does not need to persist session state
because every privileged action is independently authorized via the
role-gated dependency in core/deps.py and logged to the hash-chained audit
trail in services/audit_chain.py.

Password hashing calls the `bcrypt` library directly (rather than going
through passlib's CryptContext) to avoid the well-known passlib<->bcrypt
version-detection incompatibility between passlib 1.7.x and bcrypt>=4.1
(passlib probes `bcrypt.__about__.__version__`, which newer bcrypt
releases removed).
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt as pyjwt

from app.core.config import get_settings

settings = get_settings()

TOKEN_SUBJECT_CLAIM = "sub"
TOKEN_ROLE_CLAIM = "role"

_BCRYPT_MAX_BYTES = 72  # bcrypt silently truncates beyond this; reject longer inputs explicitly.


def hash_password(plain_password: str) -> str:
    encoded = plain_password.encode("utf-8")
    if len(encoded) > _BCRYPT_MAX_BYTES:
        raise ValueError(f"Password must be at most {_BCRYPT_MAX_BYTES} bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except ValueError:
        # Malformed hash (e.g. legacy/foreign format) — treat as a failed verification, not a crash.
        return False


def create_access_token(*, username: str, role: str, expires_minutes: int | None = None) -> str:
    expire_delta = timedelta(minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        TOKEN_SUBJECT_CLAIM: username,
        TOKEN_ROLE_CLAIM: role,
        "iat": now,
        "exp": now + expire_delta,
    }
    return pyjwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


class InvalidTokenError(Exception):
    pass


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        return pyjwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except pyjwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc
