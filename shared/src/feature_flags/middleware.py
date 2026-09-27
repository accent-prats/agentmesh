"""
FlagMiddleware — attaches a per-request GrowthBook evaluator to request.state.

Middleware runs before FastAPI route dependencies, so request.state.user is not
yet populated when this runs.  Instead we decode the JWT directly from the
Authorization header to derive user attributes.  This is safe because:
  - We only READ the token (no validation side-effects, no DB calls).
  - If the token is missing or malformed we fall back to minimal attributes —
    the auth dependency downstream still performs full validation and rejects
    the request if needed.
  - API key users (ci_service) carry no JWT, so they get the CI-safe attribute
    set (no user-segment rules can target them).

Attribute strategy
──────────────────
  JWT present      → full attribute set (id, email, role, app_access, company …)
  API key (Bearer svc_*) → ci_service attributes — stripped, never targeted
  Unauthenticated  → minimal set (app, environment) — flags return defaults
"""
from __future__ import annotations

import base64
import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .client import get_client

log = logging.getLogger(__name__)

# Paths that must remain accessible even in read-only mode
_READONLY_EXEMPT = {"/api/v1/health", "/api/v1/auth/login", "/api/v1/auth/refresh"}
_WRITE_METHODS   = {"POST", "PUT", "PATCH", "DELETE"}


class FlagMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, app_name: str, environment: str = "production") -> None:
        super().__init__(app)
        self._app_name = app_name
        self._environment = environment

    async def dispatch(self, request: Request, call_next):
        try:
            attributes = self._build_attributes(request)
            request.state.flags = get_client().evaluate(attributes)
        except RuntimeError:
            # GrowthBook client not yet initialized (e.g. health-check at startup)
            from growthbook import GrowthBook
            request.state.flags = GrowthBook(attributes={}, features={})

        # shared.maintenance.readonly-mode — reject all write operations when ON.
        # Auth and health-check endpoints are always exempt so the platform stays
        # accessible for monitoring and re-authentication during maintenance.
        if (
            request.method in _WRITE_METHODS
            and request.url.path not in _READONLY_EXEMPT
            and request.state.flags.is_on("shared.maintenance.readonly-mode")
        ):
            log.warning(
                "readonly_mode_blocked",
                method=request.method,
                path=request.url.path,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "The platform is in read-only maintenance mode. "
                              "Write operations are temporarily disabled. "
                              "Please try again later or contact your administrator.",
                    "code": "readonly_mode",
                },
            )

        return await call_next(request)

    def _build_attributes(self, request: Request) -> dict:
        base = {"app": self._app_name, "environment": self._environment}

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return base

        token = auth_header[len("Bearer "):]

        # Service API keys start with "svc_" and belong to ci_service accounts.
        # Give them a safe, minimal attribute set so they never land in
        # user-facing experiments.
        if token.startswith("svc_"):
            return {**base, "role": "ci_service"}

        # Decode JWT payload (no signature verification — that's the auth
        # dependency's job; we only need the claims for flag targeting).
        payload = _decode_jwt_payload(token)
        if payload is None:
            return base

        email = payload.get("email", "")
        return {
            **base,
            "id":         payload.get("sub", ""),
            "email":      email,
            "role":       payload.get("role", "user"),
            "app_access": list(payload.get("app_access", []) or []),
            "company":    email.split("@")[1] if "@" in email else "",
        }


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode the JWT payload without verifying the signature.

    Returns None if the token is malformed.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Add padding that JWT base64url omits
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None
