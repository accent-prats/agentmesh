"""
JWT and password utilities for the portal.

Every app on the platform (currently Culprit) shares this same SECRET_KEY
and token structure, so a token issued here is valid there without any
token exchange.
"""
import os
from datetime import datetime, timedelta, timezone

from jose import jwt
from passlib.context import CryptContext

SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES  = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS    = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


def create_access_token(
    email: str,
    role: str,
    *,
    user_id: str = "",
    full_name: str = "",
    app_access: list[str] | None = None,
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {
            "sub":        user_id or email,
            "email":      email,
            "role":       role,
            "full_name":  full_name,
            "app_access": app_access or [],
            "type":       "access",
            "exp":        expire,
        },
        SECRET_KEY, algorithm=ALGORITHM,
    )


def create_refresh_token(email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode(
        {"sub": email, "type": "refresh", "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def create_service_token(service_name: str) -> str:
    """A short-lived token another app on the platform mints for itself to
    call a Portal-internal, non-browser endpoint - distinct `type` from a
    real user's "access" token, so it can never be handed to
    `get_current_user`/`require_admin` (which both require `type == "access"`
    and a real users-table row) by mistake. Signed with the same
    `SECRET_KEY` every app already shares for SSO - see
    `portal/api/routers/ai_providers.py`'s `require_service` and Culprit's
    `security/portal_jwt.py` for the equivalent trust on that side."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    return jwt.encode(
        {"sub": service_name, "type": "service", "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
