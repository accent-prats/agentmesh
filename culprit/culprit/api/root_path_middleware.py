"""Makes FastAPI's auto-generated /docs (Swagger UI) work when this app is
reverse-proxied under a path prefix.

Found 2026-09-27: `/culprit/docs` rendered "Unable to render this
definition - the provided definition does not specify a valid version
field." FastAPI's built-in docs route computes
`openapi_url = request.scope.get("root_path", "") + app.openapi_url` and
embeds that as an *absolute* URL in the Swagger UI page - unlike every
hand-written page in this app (console/settings/report), which
deliberately uses relative paths for exactly this reason. With no
`root_path`, that came out as the site-root `/openapi.json`, which nginx
routes to Portal's SPA (its catch-all `/` location), not to Culprit -
Swagger UI then tried to parse Portal's index.html as an OpenAPI spec.

This app is reachable two ways - directly on its own port (no prefix) and
via nginx under /culprit/ - so `root_path` can't be a fixed value (a
static `--root-path` would break whichever path didn't expect it). This
is the standard fix for exactly that (see FastAPI's own "Behind a Proxy"
docs): a raw ASGI middleware that derives `scope["root_path"]` per-request
from a `X-Forwarded-Prefix` header, which nginx sets only on the prefixed
location - direct-port access never sends it, so root_path stays empty
there and nothing changes for it.
"""
from __future__ import annotations

from starlette.requests import Request


def root_path(request: Request) -> str:
    """The prefix this request was reverse-proxied under (e.g. "/culprit"),
    or "" for direct/unprefixed access. Every internal redirect this app
    issues (auth_middleware.py's redirect-to-login, main.py's /login,
    /logout) must prepend this before it becomes a `Location` header -
    found 2026-09-27 alongside the /docs bug this middleware fixes: those
    redirects used a hardcoded absolute path (e.g. "/login"), which the
    browser resolves against the *site* root, not this app's mount point -
    under /culprit/, that lands back on Portal's catch-all route instead
    of Culprit's own login page."""
    return request.scope.get("root_path") or ""


class RootPathFromHeaderMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            prefix = headers.get(b"x-forwarded-prefix")
            if prefix:
                scope["root_path"] = prefix.decode()
        await self.app(scope, receive, send)
