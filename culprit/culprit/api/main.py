"""FastAPI application entry point.

    uvicorn culprit.api.main:app --reload

Every route here is additive over the pipeline modules - the API layer
holds no pipeline logic of its own, it only wires HTTP to
culprit.pipeline / culprit.db / culprit.reporting.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from culprit import config
from culprit.api.auth_middleware import SESSION_COOKIE, RequireApiTokenMiddleware, is_authenticated
from culprit.api.root_path_middleware import RootPathFromHeaderMiddleware, root_path
from culprit.api.routes_chat import router as chat_router
from culprit.api.routes_preflight import router as preflight_router
from culprit.api.routes_runs import router as runs_router
from culprit.api.routes_settings import router as settings_router
from culprit.api.routes_verdicts import router as verdicts_router
from culprit.reporting.render import render_console_html, render_login_html, render_runs_html, render_settings_html
from culprit.scheduler.events import router as events_router

log = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # Loud, unmissable warnings for settings that silently degrade to an
    # insecure default otherwise - found in review 2026-09-27: none of
    # these were ever flagged anywhere before this, including at runtime.
    if not config.settings.api_token and not config.settings.portal_jwt_secret:
        log.warning(
            "Neither CULPRIT_API_TOKEN nor CULPRIT_PORTAL_JWT_SECRET is set - every route is open "
            "to anyone who can reach this process (no login, no bearer token, no Portal SSO "
            "required). Fine for the offline demo; set at least one before this holds real "
            "Azure/Datadog credentials or runs against a real subscription."
        )
    elif not config.settings.api_token:
        log.info(
            "CULPRIT_API_TOKEN is not set - relying solely on Portal SSO (CULPRIT_PORTAL_JWT_SECRET) "
            "for authentication. Direct script/curl access has no fallback credential."
        )
    if not config.settings.encryption_key:
        log.warning(
            "CULPRIT_ENCRYPTION_KEY is not set - settings screen secrets are being encrypted with "
            "a hardcoded, source-visible dev-only key (see culprit/security/crypto.py), which is "
            "no real protection at all. Set it before saving real Azure/Datadog credentials."
        )

    scheduler = None
    if config.settings.scheduler_enabled:
        from culprit.api import deps
        from culprit.db import repository
        from culprit.scheduler.cron import build_scheduler

        # Seeds from whatever's saved on /culprit/settings' "Scheduled
        # runs" card (falling back to CULPRIT_SCHEDULER_ENABLED/
        # CULPRIT_SCHEDULED_CRON only if nothing's ever been saved there -
        # see load_schedule_settings) - CULPRIT_SCHEDULER_ENABLED stays
        # the one thing only an env var/redeploy controls: whether *this
        # process* runs an in-process scheduler at all, vs. relying on an
        # external one (k8s CronJob, Azure Function timer) hitting
        # /runs/live itself. Everything past that (cron, window, scope,
        # pause/resume) is DB-backed and edits live via apply_schedule -
        # see routes_settings.py's PUT /settings/schedule.
        with deps.get_session_factory()() as session:
            schedule_cfg = repository.load_schedule_settings(session)

        scheduler = build_scheduler(
            schedule_cfg=schedule_cfg,
            pre_flight_interval_minutes=config.settings.preflight_interval_minutes,
        )
        scheduler.start()
        log.info(
            "In-process scheduler started - scheduled_cycle %s (cron '%s', scope '%s'), "
            "pre_flight_check every %d min",
            "enabled" if schedule_cfg.enabled else "disabled (enable it on /culprit/settings)",
            schedule_cfg.cron_expression, schedule_cfg.scope_name, config.settings.preflight_interval_minutes,
        )

    _app.state.scheduler = scheduler

    yield

    if scheduler is not None:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="Culprit",
    description="Autonomous root-cause analysis for failed Azure Update Manager patch deployments.",
    version="0.1.0",
    lifespan=_lifespan,
)


# Wide-open origins are safe here specifically because allow_credentials is
# NOT set (defaults to False in Starlette) - a cross-origin page cannot get
# our session cookie sent along with its requests, so it can only reach an
# authenticated route if it already somehow knows the bearer token. Scope
# this down to a real origin anyway if a separate frontend is ever added.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequireApiTokenMiddleware)

# Vendored Tailwind/Lucide (reporting/static/) - the server-rendered pages
# used to load these live from cdn.tailwindcss.com/cdn.jsdelivr.net, which
# breaks every page's styling on a deployment that can't reach the public
# internet (found 2026-09-29 on a network-restricted environment: every
# page rendered as plain unstyled HTML). auth_middleware.py's
# _PUBLIC_PATH_PREFIX exempts this path from login so the login page
# itself can fetch its own CSS/JS.
#
# A plain route, not `app.mount("/static", StaticFiles(...))` - found while
# verifying this fix under nginx's /culprit/ prefix: `Mount.matches()`
# accumulates `X-Forwarded-Prefix`'s value onto `scope["root_path"]` (see
# `root_path_middleware.py`), but nginx's own rewrite already stripped that
# prefix from `scope["path"]` before this app ever sees it - `root_path` no
# longer being an actual prefix of `path` makes Starlette's route-path
# resolution fall back to the *unstripped* path a second time inside
# StaticFiles, so it looked up "static/tailwind.js" relative to a directory
# that already *is* .../static, i.e. a nonexistent .../static/static/. A
# plain `@app.get` route never hits that accumulation - FastAPI resolves
# `file_path` correctly regardless - and calls `get_response()` directly
# with the already-resolved relative path instead of re-deriving it.
_STATIC_DIR = Path(__file__).parent.parent / "reporting" / "static"
_static_files = StaticFiles(directory=str(_STATIC_DIR))


@app.get("/static/{file_path:path}", include_in_schema=False)
async def _serve_static(file_path: str, request: Request):
    return await _static_files.get_response(file_path, request.scope)

app.include_router(runs_router)
app.include_router(settings_router)
app.include_router(verdicts_router)
app.include_router(chat_router)
app.include_router(events_router)
app.include_router(preflight_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def console() -> str:
    """The AgentMesh launcher's 'Launch' target for Culprit - now a real
    dashboard (the latest completed run's headline numbers, a compliance
    trend, and a top-causes breakdown - see db/repository.py::
    build_dashboard_summary) rather than just a launcher. The demo/live
    triggers are still here too; everything they call (POST /runs/demo,
    GET /runs/{id}/report.html) is a route already defined above."""
    from culprit.api import deps
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        dashboard = repository.build_dashboard_summary(session)
    return render_console_html(demo_enabled=config.settings.demo_enabled, dashboard=dashboard)


@app.get("/settings", response_class=HTMLResponse)
def settings_page() -> str:
    """Azure/Datadog connection settings - see culprit/api/routes_settings.py
    for the API this page reads and writes."""
    return render_settings_html()


@app.get("/runs.html", response_class=HTMLResponse)
def runs_page() -> str:
    """Every run Culprit has diagnosed, most recent first - "which update
    jobs is Culprit monitoring" (culprit/db/repository.py::list_runs)."""
    from culprit.api import deps
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        runs = repository.list_runs(session)
    return render_runs_html(runs, demo_enabled=config.settings.demo_enabled)


@app.get("/login", response_model=None)
def login_page(request: Request, next: str = "/") -> HTMLResponse | RedirectResponse:
    auth_disabled = not config.settings.api_token and not config.settings.portal_jwt_secret
    already_in = is_authenticated(request, config.settings.api_token, config.settings.portal_jwt_secret)
    if auth_disabled or already_in:
        # Nothing to protect, or already signed in (shared token or Portal
        # SSO) - don't make either case sit at a login form with nothing
        # useful to do. Note this does NOT cover the one-time
        # ?auth_token=<jwt> handoff - that's the middleware's job
        # (auth_middleware.py), since it also needs to set a cookie.
        return RedirectResponse(url=f"{root_path(request)}{next}", status_code=303)
    return HTMLResponse(render_login_html(next_path=next))


@app.post("/login", response_model=None)
async def login_submit(request: Request) -> HTMLResponse | RedirectResponse:
    form = await request.form()
    next_path = str(form.get("next") or "/")
    prefix = root_path(request)
    if not config.settings.api_token:
        return RedirectResponse(url=f"{prefix}{next_path}", status_code=303)

    submitted = str(form.get("token") or "")
    if submitted != config.settings.api_token:
        return HTMLResponse(
            render_login_html(next_path=next_path, error="Incorrect token."), status_code=401
        )

    response = RedirectResponse(url=f"{prefix}{next_path}", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        config.settings.api_token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,  # 30 days - this is a shared operator token, not a per-user login
    )
    return response


@app.get("/logout")
def logout(request: Request) -> RedirectResponse:
    response = RedirectResponse(url=f"{root_path(request)}/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


# Must be the outermost ASGI layer, added last, after every route and
# middleware above is registered on the FastAPI instance itself - see
# root_path_middleware.py for why this exists (fixes /docs under the
# nginx-proxied /culprit/ mount). Rebinds the module-level `app` name that
# `uvicorn culprit.api.main:app` and every test's `from culprit.api.main
# import app` resolve, from the FastAPI instance to this wrapper - both are
# valid ASGI callables, so nothing above this line needs to change.
app = RootPathFromHeaderMiddleware(app)
