"""
FRD ref: FRD-AUTH-01/02/04 — rate-limited, audited login issuing a
short-lived JWT session token.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, get_db
from app.core.rate_limit import RateLimitExceeded, RateLimiter
from app.core.security import create_access_token, verify_password
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.user import UserOut
from app.services.audit_chain import append_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])

_settings = get_settings()
_login_rate_limiter = RateLimiter(
    max_attempts=_settings.LOGIN_RATE_LIMIT_ATTEMPTS,
    window_seconds=_settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
)


def _client_key(request: Request, username: str) -> str:
    client_host = request.client.host if request.client else "unknown"
    return f"{username}:{client_host}"


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    key = _client_key(request, payload.username)
    try:
        _login_rate_limiter.check(key)
    except RateLimitExceeded as exc:
        append_audit_event(
            db,
            actor=payload.username,
            action="login_rate_limited",
            resource="auth:login",
            details={"retry_after_seconds": exc.retry_after_seconds},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        ) from exc

    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not user.is_active or not verify_password(payload.password, user.hashed_password):
        append_audit_event(
            db, actor=payload.username, action="login_failed", resource="auth:login", details={}
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    _login_rate_limiter.reset(key)
    token = create_access_token(username=user.username, role=user.role)
    append_audit_event(db, actor=user.username, action="login_success", resource="auth:login", details={})

    return TokenResponse(access_token=token, username=user.username, role=user.role)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
