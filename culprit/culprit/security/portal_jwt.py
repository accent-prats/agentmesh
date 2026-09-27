"""Validates the AgentMesh Portal's JWT so an already-authenticated
platform user isn't asked to separately sign in to Culprit with the
unrelated shared `CULPRIT_API_TOKEN`.

Found 2026-09-27: a user who launched Culprit from the AgentMesh
launcher - already logged into Portal - was bounced to Culprit's own
"enter the shared access token" screen, which has nothing to do with
their platform identity. Portal already signs tokens with a secret
Culprit can share and trust without a token exchange (see
`portal/security.py`'s own docstring); this makes Culprit the same
kind of platform member instead of a separate walled garden.

Deliberately does **not** look the user up in a database - Culprit has no
`users` table (it doesn't share Postgres with the rest of the platform,
by design; see the repo's docker-compose.yml). Everything needed is
already in the token's own claims: `app_access` is the one authorization
check that matters for an ordinary user - was this user actually granted
Culprit access via the Admin screen's per-user checkboxes? - and
`email`/`role` are there if a future screen wants to display who's signed
in.

`role` is *also* an authorization input, not just display data - see the
admin-bypass note below.
"""
from __future__ import annotations

from jose import JWTError, jwt

_ALGORITHM = "HS256"

# Mirrors portal/api/routers/apps.py::list_accessible_apps exactly: an
# admin (or the ci_service role) sees/uses every non-hidden app regardless
# of their own app_access column, specifically so nobody has to remember
# to tick a box for themselves when a new app ships. Found 2026-09-27,
# immediately after the first Portal-SSO fix: create_access_token()
# embeds the user's *raw* app_access DB column into the JWT with no admin
# bypass at all (that bypass only exists in apps.py's launcher-visibility
# query) - so an admin's own token often doesn't list "culprit" even
# though they can see and click the card. Without this, every admin would
# need an explicit grant just to use a tool their role already lets them
# see, which is inconsistent with how the rest of the platform treats them.
_ADMIN_ROLES = {"admin", "ci_service"}


def validate_portal_token(token: str, secret: str) -> dict | None:
    """Returns the decoded claims if `token` is a Portal-issued access
    token, signed with `secret`, not expired, and either an admin/ci_service
    role or granted "culprit" in its app_access list - otherwise None.
    Every failure mode (no secret configured, malformed token, expired,
    wrong signature, wrong token type, access not granted) is deliberately
    collapsed into the same `None` - the caller only ever needs "is this
    good enough to let the request through," never why it wasn't."""
    if not secret or not token:
        return None
    try:
        payload = jwt.decode(token, secret, algorithms=[_ALGORITHM])
    except JWTError:
        return None
    if payload.get("type") != "access":
        return None
    if payload.get("role") in _ADMIN_ROLES:
        return payload
    if "culprit" not in (payload.get("app_access") or []):
        return None
    return payload


def renew_portal_token(payload: dict, secret: str, ttl_seconds: int) -> str:
    """Mints a fresh token carrying the same claims as `payload` (what
    `validate_portal_token` returned) but a new `exp`, `ttl_seconds` out
    from now - what `auth_middleware.py`'s sliding-session renewal uses to
    keep an actively-browsing user's cookie valid past the moment Portal
    originally issued it, without a round-trip to Portal's own
    `/api/auth/refresh` endpoint. Safe because Culprit already holds the
    same signing secret Portal used to issue the original token - it
    isn't inventing a claim, just re-signing the ones already validated."""
    from datetime import datetime, timedelta, timezone

    fresh = {**payload, "exp": datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)}
    return jwt.encode(fresh, secret, algorithm=_ALGORITHM)
