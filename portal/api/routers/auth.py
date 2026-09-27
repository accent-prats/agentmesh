"""Portal auth endpoints — login, refresh, me, user app-access management."""
from fastapi import APIRouter, Depends, HTTPException, status
from jose import JWTError
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.db import get_db
from portal.security import (
    create_access_token, create_refresh_token, decode_token,
    hash_password, verify_password,
)
from portal.dependencies import get_current_user, require_admin
from portal.logging_config import get_logger

log = get_logger(__name__)
router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    app_access: list[str] = []


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    app_access: list[str]


class AppAccessUpdate(BaseModel):
    app_access: list[str]

    @field_validator("app_access")
    @classmethod
    def validate_apps(cls, v: list[str]) -> list[str]:
        valid = {"culprit"}
        for app in v:
            if app not in valid:
                raise ValueError(f"app must be one of {valid}")
        return v


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: str = "user"
    app_access: list[str] = []

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        valid = {"admin", "user", "read_only", "ci_service"}
        if v not in valid:
            raise ValueError(f"role must be one of {valid}")
        return v


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    app_access: list[str] | None = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is None:
            return v
        valid = {"admin", "user", "read_only", "ci_service"}
        if v not in valid:
            raise ValueError(f"role must be one of {valid}")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class AdminResetPasswordRequest(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    from portal.db import User
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account disabled")

    log.info("portal_login", email=user.email, app_access=user.app_access)
    return TokenResponse(
        access_token=create_access_token(
            user.email, user.role,
            user_id=str(user.id), full_name=user.full_name, app_access=user.app_access or [],
        ),
        refresh_token=create_refresh_token(user.email),
        app_access=user.app_access or [],
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    from portal.db import User
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise ValueError("not a refresh token")
        email = payload["sub"]
    except (JWTError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return TokenResponse(
        access_token=create_access_token(
            user.email, user.role,
            user_id=str(user.id), full_name=user.full_name, app_access=user.app_access or [],
        ),
        refresh_token=create_refresh_token(user.email),
        app_access=user.app_access or [],
    )


@router.get("/me", response_model=UserResponse)
async def me(user=Depends(get_current_user)):
    return UserResponse(
        id=str(user.id), email=user.email, full_name=user.full_name,
        role=user.role, is_active=user.is_active, app_access=user.app_access or [],
    )


@router.get("/users", response_model=list[UserResponse])
async def list_users(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    """Admin: list all platform users."""
    from portal.db import User
    from sqlalchemy import asc
    result = await db.execute(select(User).order_by(asc(User.created_at)))
    users = result.scalars().all()
    return [
        UserResponse(
            id=str(u.id), email=u.email, full_name=u.full_name,
            role=u.role, is_active=u.is_active, app_access=u.app_access or [],
        )
        for u in users
    ]


@router.post("/users", response_model=UserResponse, status_code=201)
async def create_user(body: UserCreate, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    """Admin: create a new platform user."""
    from portal.db import User
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=body.email,
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        role=body.role,
        is_active=True,
        app_access=body.app_access,
    )
    db.add(user)
    await db.flush()
    log.info("user_created", email=user.email, role=user.role, created_by="admin")
    return UserResponse(
        id=str(user.id), email=user.email, full_name=user.full_name,
        role=user.role, is_active=user.is_active, app_access=user.app_access or [],
    )


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    """Admin: update a user's role, active status, or app access."""
    from portal.db import User
    import uuid
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.app_access is not None:
        user.app_access = body.app_access
    await db.flush()
    log.info("user_updated", email=user.email, role=user.role, is_active=user.is_active)
    return UserResponse(
        id=str(user.id), email=user.email, full_name=user.full_name,
        role=user.role, is_active=user.is_active, app_access=user.app_access or [],
    )


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Any authenticated user: change their own password (requires current password)."""
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if body.current_password == body.new_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current password")

    user.hashed_password = hash_password(body.new_password)
    await db.flush()
    log.info("password_changed", email=user.email)
    return {"ok": True}


@router.post("/users/{user_id}/reset-password")
async def admin_reset_password(
    user_id: str,
    body: AdminResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    """Admin: reset any user's password without requiring the current password."""
    from portal.db import User
    import uuid
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.hashed_password = hash_password(body.new_password)
    await db.flush()
    log.info("password_reset_by_admin", target_email=target.email)
    return {"ok": True}


@router.put("/users/{user_id}/apps", response_model=UserResponse)
async def update_user_apps(
    user_id: str,
    body: AppAccessUpdate,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    """Admin: grant or revoke a user's access to specific platform apps."""
    from portal.db import User
    import uuid
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.app_access = body.app_access
    await db.flush()
    log.info("app_access_updated", user=user.email, app_access=body.app_access)
    return UserResponse(
        id=str(user.id), email=user.email, full_name=user.full_name,
        role=user.role, is_active=user.is_active, app_access=user.app_access,
    )
