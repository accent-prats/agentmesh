"""Gates every route behind either of two independent credentials:

  1. A shared token (`CULPRIT_API_TOKEN`) - for standalone use (no Portal),
     scripts, and curl. A **cookie** (`culprit_session`) for browsers - set
     once at `/login`, then attached automatically on every subsequent
     request - or an `Authorization: Bearer <token>` header.
  2. The AgentMesh Portal's own JWT (`CULPRIT_PORTAL_JWT_SECRET`) - so a
     user who is already signed into the platform and launched Culprit
     from the AgentMesh launcher is let straight in, instead of hitting a
     second, unrelated login wall. See `security/portal_jwt.py`.

Found in review (2026-09-27): the app had zero authentication anywhere -
anyone who could reach the URL could overwrite Azure/Datadog settings,
trigger a live run against a real subscription, or inject fabricated
verdicts. #1 above closed that. Found immediately after shipping #1 (a
real user hit it): an authenticated Portal user got the same "enter a
shared token" wall as an anonymous one, because #1 didn't know about
Portal's own session at all. #2 closes that.

If **neither** env var is ever set, auth is disabled entirely (fail
*open*, loudly warned about at startup in `main.py`) - the same
"insecure default, but you can't miss the warning" shape as
`security/crypto.py`'s dev-only encryption key, and what keeps the demo
and the test suite (which never set either var) working with zero
configuration. Either one alone is enough to enable enforcement; both can
be configured at once (Portal SSO for platform users, the shared token
still available for scripts/curl).
"""
from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from culprit import config
from culprit.api.root_path_middleware import root_path
from culprit.security.portal_jwt import renew_portal_token, validate_portal_token

SESSION_COOKIE = "culprit_session"

# Event Grid's own subscription-validation handshake can't carry our
# cookie or bearer header - it's a different trust boundary (Azure
# calling us), not a human or script using the app. /login and /health
# obviously can't require the credential they exist to grant/report on.
_PUBLIC_PATHS = {"/health", "/login", "/webhooks/event-grid"}

# Vendored CSS/icon assets (reporting/static/ - see main.py's StaticFiles
# mount) - these hold no data of any kind, and the login page itself has
# to be able to fetch them before a user has any credential at all, or
# the login screen would render unstyled (the exact bug this vendoring
# was added to fix - see the module docstring's own history for why
# these used to be a Tailwind/Lucide CDN script tag instead).
_PUBLIC_PATH_PREFIX = "/static/"

# Portal's own access tokens are short-lived (ACCESS_TOKEN_EXPIRE_MINUTES,
# 60 by default) - matched here so the cookie we set from a validated one
# doesn't imply a longer session than the JWT inside it actually grants.
# This is a *sliding* window, not a hard one, though: RequireApiTokenMiddleware
# re-signs and re-sets this cookie on every authenticated request (see
# dispatch() below), so an actively-browsing user's session is "60 minutes
# since your last click", not "60 minutes since you logged in" - found in
# review 2026-09-27, a real user got bounced to the shared-token login
# screen mid-session with no working way back in (that token is an
# operator secret, not something an ordinary AgentMesh user has).
_PORTAL_COOKIE_MAX_AGE_SECONDS = 60 * 60


def _token_matches(candidate: str | None, expected: str) -> bool:
    if not expected or not candidate:
        return False
    return hmac.compare_digest(candidate, expected)


def is_authenticated(request: Request, expected_token: str, portal_jwt_secret: str = "") -> bool:
    """True if `request` carries a valid credential of either kind - the
    shared token (cookie or Bearer header) or a Portal JWT with "culprit"
    in its app_access (cookie or Bearer header; the query-string
    `auth_token` Portal's launcher appends is handled separately by the
    middleware below, since accepting it also means setting a cookie)."""
    cookie_value = request.cookies.get(SESSION_COOKIE)
    if _token_matches(cookie_value, expected_token):
        return True
    if cookie_value and validate_portal_token(cookie_value, portal_jwt_secret):
        return True

    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        candidate = auth_header[len("Bearer ") :]
        if _token_matches(candidate, expected_token):
            return True
        if validate_portal_token(candidate, portal_jwt_secret):
            return True

    return False


class RequireApiTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Read via the module (config.settings), not a
        # `from culprit.config import settings` name import - the latter
        # binds to whatever object existed at import time, the same class
        # of bug the routers hit with `culprit.api.deps` earlier (fixed by
        # switching those to `from culprit.api import deps` + `deps.x()`).
        # settings is a frozen dataclass, so tests replace the whole
        # `config.settings` object rather than mutating a field on it.
        token = config.settings.api_token
        portal_jwt_secret = config.settings.portal_jwt_secret
        if not token and not portal_jwt_secret:
            # Auth disabled entirely - see the module docstring. main.py
            # warns at startup; this is the actual fail-open enforcement point.
            return await call_next(request)

        if request.url.path in _PUBLIC_PATHS or request.url.path.startswith(_PUBLIC_PATH_PREFIX):
            return await call_next(request)

        if is_authenticated(request, token, portal_jwt_secret):
            response = await call_next(request)
            _renew_session_cookie_if_portal_backed(request, response, portal_jwt_secret)
            return response

        # One-time SSO handoff: the AgentMesh launcher's "Launch" link
        # appends `?auth_token=<portal JWT>` on the initial navigation only
        # - the page's own fetch() calls never see the query string, so a
        # valid one here is let through *and* persisted as a cookie, or
        # every request after this first one would fail auth again.
        query_token = request.query_params.get("auth_token")
        if query_token and validate_portal_token(query_token, portal_jwt_secret):
            response = await call_next(request)
            response.set_cookie(
                SESSION_COOKIE, query_token, httponly=True, samesite="lax", max_age=_PORTAL_COOKIE_MAX_AGE_SECONDS
            )
            return response

        if "text/html" in request.headers.get("accept", ""):
            next_path = request.url.path
            if request.url.query:
                next_path += "?" + request.url.query
            return RedirectResponse(url=f"{root_path(request)}/login?next={next_path}", status_code=303)

        return JSONResponse({"detail": "Unauthorized"}, status_code=401)


def _renew_session_cookie_if_portal_backed(request: Request, response, portal_jwt_secret: str) -> None:
    """Sliding-session renewal - browser-cookie sessions backed by a
    Portal JWT only, never the shared `CULPRIT_API_TOKEN` and never a
    script's `Authorization: Bearer` header (neither of those should get
    a `Set-Cookie` at all; a script re-sends its own credential every
    call and has no cookie jar to benefit from one).

    Independently re-checks the cookie itself rather than trusting
    *why* `is_authenticated()` upstream returned True, so this can't
    accidentally fire for the shared-token-via-cookie case."""
    cookie_value = request.cookies.get(SESSION_COOKIE)
    if not cookie_value:
        return
    payload = validate_portal_token(cookie_value, portal_jwt_secret)
    if payload is None:
        return  # the shared token, or already invalid - nothing to renew
    renewed = renew_portal_token(payload, portal_jwt_secret, _PORTAL_COOKIE_MAX_AGE_SECONDS)
    response.set_cookie(
        SESSION_COOKIE, renewed, httponly=True, samesite="lax", max_age=_PORTAL_COOKIE_MAX_AGE_SECONDS
    )
