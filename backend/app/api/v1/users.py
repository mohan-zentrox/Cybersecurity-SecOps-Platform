"""
FRD ref: FRD-AUTH-05 — user lifecycle management.

Without this router the platform has no way to create an operator except
by hand-inserting a row, which is why it previously could not be deployed.
Creation, role changes, deactivation, and admin password resets are all
admin-gated and audited; password *self*-change is available to any
authenticated user and requires the current password.

Users are deactivated, never hard-deleted: `Alert.assigned_to` and
`Case.assigned_to` reference them, and an audit trail that points at a
vanished user id is not much of an audit trail.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_roles
from app.core.pagination import Page, PageParams, page_params, paginate
from app.core.security import hash_password, verify_password
from app.models.user import AppRole, User
from app.schemas.user import PasswordChange, PasswordReset, UserCreate, UserOut, UserUpdate
from app.services.audit_chain import append_audit_event

router = APIRouter(prefix="/users", tags=["users"])

_ADMIN_ONLY = (AppRole.ADMIN,)


def _get_user_or_404(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("", response_model=Page[UserOut])
def list_users(
    role: str | None = None,
    is_active: bool | None = None,
    params: PageParams = Depends(page_params),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Page[UserOut]:
    """Any authenticated user may list users — the console needs it to render
    assignee pickers. Only non-sensitive fields are exposed (no password hash)."""
    query = db.query(User)
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active.is_(is_active))
    rows, total = paginate(db, query.order_by(User.id.asc()), params)
    return Page[UserOut](
        items=[UserOut.model_validate(r) for r in rows],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    current_user: User = Depends(require_roles(*_ADMIN_ONLY)),
    db: Session = Depends(get_db),
) -> User:
    clash = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == str(payload.email)))
        .first()
    )
    if clash is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username or email is already in use"
        )

    user = User(
        username=payload.username,
        email=str(payload.email),
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    append_audit_event(
        db,
        actor=current_user.username,
        action="user_created",
        resource=f"user:{user.id}",
        details={"username": user.username, "role": user.role},
    )
    return user


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> User:
    return _get_user_or_404(db, user_id)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    current_user: User = Depends(require_roles(*_ADMIN_ONLY)),
    db: Session = Depends(get_db),
) -> User:
    user = _get_user_or_404(db, user_id)
    changes: dict[str, object] = {}

    if payload.email is not None and str(payload.email) != user.email:
        if db.query(User).filter(User.email == str(payload.email), User.id != user.id).first():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already in use")
        changes["email"] = str(payload.email)
        user.email = str(payload.email)
    if payload.role is not None and payload.role != user.role:
        changes["role"] = payload.role
        user.role = payload.role
    if payload.is_active is not None and payload.is_active != user.is_active:
        # Guard against locking everyone out of administration.
        if not payload.is_active and user.role == AppRole.ADMIN:
            remaining = (
                db.query(User)
                .filter(User.role == AppRole.ADMIN, User.is_active.is_(True), User.id != user.id)
                .count()
            )
            if remaining == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate the last active administrator",
                )
        changes["is_active"] = payload.is_active
        user.is_active = payload.is_active

    db.commit()
    db.refresh(user)

    if changes:
        append_audit_event(
            db,
            actor=current_user.username,
            action="user_updated",
            resource=f"user:{user.id}",
            details=changes,
        )
    return user


@router.delete("/{user_id}", response_model=UserOut)
def deactivate_user(
    user_id: int,
    current_user: User = Depends(require_roles(*_ADMIN_ONLY)),
    db: Session = Depends(get_db),
) -> User:
    """Soft-delete: deactivate rather than remove, preserving referential integrity."""
    user = _get_user_or_404(db, user_id)
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate your own account"
        )
    if user.role == AppRole.ADMIN:
        remaining = (
            db.query(User)
            .filter(User.role == AppRole.ADMIN, User.is_active.is_(True), User.id != user.id)
            .count()
        )
        if remaining == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate the last active administrator",
            )

    user.is_active = False
    db.commit()
    db.refresh(user)

    append_audit_event(
        db,
        actor=current_user.username,
        action="user_deactivated",
        resource=f"user:{user.id}",
        details={"username": user.username},
    )
    return user


@router.post("/{user_id}/password-reset", response_model=UserOut)
def reset_password(
    user_id: int,
    payload: PasswordReset,
    current_user: User = Depends(require_roles(*_ADMIN_ONLY)),
    db: Session = Depends(get_db),
) -> User:
    user = _get_user_or_404(db, user_id)
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    db.refresh(user)

    append_audit_event(
        db,
        actor=current_user.username,
        action="user_password_reset",
        resource=f"user:{user.id}",
        details={"username": user.username},
    )
    return user


@router.post("/me/password", response_model=UserOut)
def change_own_password(
    payload: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    if not verify_password(payload.current_password, current_user.hashed_password):
        append_audit_event(
            db,
            actor=current_user.username,
            action="password_change_failed",
            resource=f"user:{current_user.id}",
            details={"reason": "current password did not match"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect"
        )

    current_user.hashed_password = hash_password(payload.new_password)
    db.commit()
    db.refresh(current_user)

    append_audit_event(
        db,
        actor=current_user.username,
        action="password_changed",
        resource=f"user:{current_user.id}",
        details={},
    )
    return current_user
