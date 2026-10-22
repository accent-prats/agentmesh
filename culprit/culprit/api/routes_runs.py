"""Run lifecycle routes: trigger, list, and read back reports.

`POST /runs/demo` is the ad-hoc trigger path used by the event demo and by
anyone kicking the tires without live Azure/Datadog credentials wired up -
it runs the synthetic scenario end to end through the same Pipeline class
production would use (culprit/pipeline/orchestrator.py). A production
deployment adds a sibling route (or the scheduler in culprit/scheduler/)
that calls `collect_all()` against real collectors first and then the
same `Pipeline.run()` - nothing else changes.
"""
from __future__ import annotations

import logging

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from culprit.api import deps
from culprit.config import settings
from culprit.models.installation_report import InstallationReport
from culprit.models.report import FleetReport

log = logging.getLogger(__name__)

_DECRYPT_ERROR_DETAIL = (
    "Stored Azure settings could not be decrypted - CULPRIT_ENCRYPTION_KEY likely changed "
    "since they were saved. Re-enter them on /culprit/settings."
)

router = APIRouter(prefix="/runs", tags=["runs"])


class LiveRunRequest(BaseModel):
    window_hours: int = Field(default=24, ge=1, le=720)
    # "Full fleet scan" rather than the old bare "live" - that literal
    # string showed up, unexplained and identical across every run, as the
    # "Update job" column on /runs and as the title of every report built
    # from an ad-hoc trigger (fleet_report.html.j2, installation_report.
    # html.j2, email_report.html.j2 all key off PatchRun.scope_name).
    scope_name: str = "Full fleet scan"


def _notify_if_configured(report: FleetReport, request: Request) -> None:
    """Push the digest to whichever webhook is configured (proposal
    Section 10: "delivery meets people where they already are"). Best-
    effort - a webhook outage must never fail the run that already
    completed successfully, so any error here is logged and swallowed."""
    webhook = settings.teams_webhook_url or settings.slack_webhook_url
    if not webhook:
        return
    try:
        from culprit.reporting.notify import post_to_slack, post_to_teams, report_url_from_request

        poster = post_to_teams if settings.teams_webhook_url else post_to_slack
        response = poster(webhook, report, report_url=report_url_from_request(request, report.run.run_id))
        log.info("Posted digest for run %s to webhook - status %s", report.run.run_id, response.status_code)
    except Exception:  # noqa: BLE001 - a notification failure must not fail the run
        log.exception("Failed to post digest for run %s to webhook", report.run.run_id)


@router.post("/demo", response_model=FleetReport)
def trigger_demo_run(request: Request) -> FleetReport:
    from culprit import config as config_module
    from culprit.db import repository
    from culprit.demo.generate_scenario import EXCLUDED_COUNT, build_scenario, fabricate_non_failure_outcomes
    from culprit.pipeline.installation_report import build_installation_report
    from culprit.pipeline.orchestrator import Pipeline

    # Via the module, not the `settings` name already imported above (that
    # binds to whatever Settings instance existed at import time - see
    # auth_middleware.py's own docstring on this exact gotcha) - a test
    # flipping this off replaces the whole `config.settings` object, which
    # only a fresh module-attribute read picks up. 404, not 403 - a
    # deployment with this off shouldn't reveal the route exists at all.
    if not config_module.settings.demo_enabled:
        raise HTTPException(status_code=404)

    run, bundles = build_scenario()
    pipeline = Pipeline(
        session_factory=deps.get_session_factory(),
        rca_agent=deps.get_rca_agent(),
        retrieval_store=deps.get_retrieval_store(),
    )
    output = pipeline.run(run, bundles)
    with deps.get_session_factory()() as session:
        report = repository.load_fleet_report(session, output.run.run_id)

    # Same build as the live path (pipeline/live_run.py::execute_live_run)
    # - see pipeline/installation_report.py::build_installation_report's
    # own docstring. Best-effort, same reasoning as the live path's own
    # try/except: must not fail a demo run that already completed.
    try:
        non_failure_rows = fabricate_non_failure_outcomes()
        installation_report = build_installation_report(run, bundles, report, non_failure_rows, EXCLUDED_COUNT)
        with deps.get_session_factory()() as session:
            repository.save_installation_report(
                session, run.run_id, installation_report.rows, installation_report.excluded_count,
            )
    except Exception:
        log.exception("Failed to build the Patch Installation Report for demo run %s", run.run_id)

    _notify_if_configured(report, request)
    return report


@router.post("/live", response_model=FleetReport)
def trigger_live_run(request: Request, body: LiveRunRequest = LiveRunRequest()) -> FleetReport:
    """Runs the real pipeline against whatever's configured on
    /culprit/settings - see culprit/pipeline/live_run.py::execute_live_run
    for the shared discovery -> collect -> diagnose path this and the
    scheduler both use."""
    from culprit.models.patch_run import TriggerMode
    from culprit.pipeline.live_run import NoSubscriptionConfigured, execute_live_run

    try:
        report = execute_live_run(
            window_hours=body.window_hours, scope_name=body.scope_name, trigger_mode=TriggerMode.AD_HOC
        )
    except NoSubscriptionConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Azure SDK not installed in this deployment (pip install 'culprit[azure]'): {exc}",
        ) from exc
    except InvalidToken as exc:
        raise HTTPException(status_code=500, detail=_DECRYPT_ERROR_DETAIL) from exc
    except Exception as exc:  # noqa: BLE001 - surface the real Azure/pipeline error rather than a generic 500
        # Found 2026-10-16: this branch raised the flattened one-line
        # HTTPException detail but never actually logged the real
        # exception anywhere - a live run failing with e.g. "The read
        # operation timed out" (which could be a Resource Graph call, a
        # Run Command poll, or now an RCA provider's own HTTP call
        # timing out) left no way to tell which one from the container's
        # own logs, only a flattened message in the browser. Full
        # traceback now reaches the logs before the UI-facing detail is
        # built from the same exception.
        log.exception("Live run failed")
        # No "Live run failed: " prefix here - console.html.j2's own catch
        # block already prepends that for every error branch above too
        # (none of which prefix their own `detail`); this one used to
        # double it up into "Live run failed: Live run failed: ...".
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    _notify_if_configured(report, request)
    return report


@router.get("/{run_id}/report", response_model=FleetReport)
def get_report(run_id: str) -> FleetReport:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        report = repository.load_fleet_report(session, run_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return report


@router.get("/{run_id}/report.html")
def get_report_html(run_id: str):
    from fastapi.responses import HTMLResponse

    from culprit.db import repository
    from culprit.models.verdict import compute_family_precision
    from culprit.reporting.render import render_fleet_report_html

    with deps.get_session_factory()() as session:
        report = repository.load_fleet_report(session, run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        # Read fresh on every render, same as the execute route itself -
        # this is what lets the "eligible once X clears review: N/50..."
        # message stay accurate as verdicts are submitted, not a stale
        # snapshot from whenever the page was last generated. The gate
        # values themselves are read the same way (DB-backed, falling
        # back to config.settings) so a just-saved Settings change shows
        # up here immediately too - see repository.py::get_current_promotion_gate.
        family_precision = compute_family_precision(repository.all_verdicts(session))
        threshold, min_sample = repository.get_current_promotion_gate(session)
        # Found by review 2026-10-22: this used to read smtp_settings_view()
        # unconditionally, so the "Email report" widget below gated itself
        # on SMTP's own configured-state regardless of which email method
        # is actually active - for a deployment that adopts Microsoft 365
        # OAuth and never configures SMTP (precisely the "later we switch
        # to this option" scenario the OAuth feature was built for), the
        # button vanished entirely even though POST /runs/{run_id}/email
        # itself worked fine via a direct API call. Mirrors routes_
        # notifications.py::send_report_email's own active-method branch.
        if repository.load_email_method(session) == "oauth":
            email_cfg = repository.email_oauth_settings_view(session)
        else:
            email_cfg = repository.smtp_settings_view(session)
        # Found in review: the "View installation report" link was
        # unconditional, so a run from before this feature existed (or
        # one where the best-effort build in live_run.py/trigger_demo_run
        # silently failed) showed a working-looking link that 404'd with
        # a raw JSON error instead of the app's own styled pages.
        installation_report_available = repository.installation_report_exists(session, run_id)
        tz_name = repository.load_display_timezone_settings(session).timezone
    return HTMLResponse(render_fleet_report_html(
        report, family_precision=family_precision, promotion_threshold=threshold, promotion_min_sample=min_sample,
        email_configured=email_cfg.configured, default_recipients=email_cfg.default_recipients,
        installation_report_available=installation_report_available, tz_name=tz_name,
    ))


@router.get("/{run_id}/installation-report", response_model=InstallationReport)
def get_installation_report(run_id: str) -> InstallationReport:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        report = repository.load_installation_report(session, run_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return report


@router.get("/{run_id}/installation-report.html")
def get_installation_report_html(run_id: str):
    """The Azure Update Manager-style full-fleet view (models/
    installation_report.py) - a sibling to report.html, not a replacement:
    that page stays the cause-clustering/RCA view, this one mirrors the
    legacy per-machine report the team is used to. 404s if the run's
    installation report was never built (e.g. a run from before this
    feature existed, or the best-effort build failed - see
    pipeline/live_run.py's own try/except around it) rather than
    rendering a confusing empty page."""
    from fastapi.responses import HTMLResponse

    from culprit.db import repository
    from culprit.reporting.render import render_installation_report_html

    with deps.get_session_factory()() as session:
        report = repository.load_installation_report(session, run_id)
        tz_name = repository.load_display_timezone_settings(session).timezone
    if report is None:
        raise HTTPException(status_code=404, detail=f"No installation report for run {run_id}")
    return HTMLResponse(render_installation_report_html(report, tz_name=tz_name))


@router.get("/{run_id}/machines/{vm_name}.html")
def get_machine_html(run_id: str, vm_name: str):
    """The report's third altitude (proposal Section 8) - one machine's
    own deviation from its cluster's representative member."""
    from fastapi.responses import HTMLResponse

    from culprit.db import repository
    from culprit.reporting.render import render_machine_html

    with deps.get_session_factory()() as session:
        detail = repository.get_machine_detail(session, run_id, vm_name)
        tz_name = repository.load_display_timezone_settings(session).timezone
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Machine {vm_name} not found in run {run_id}")
    return HTMLResponse(
        render_machine_html(
            detail.cluster, detail.member, detail.result, detail.outcome, detail.collection_gaps,
            detail.patch_extension_status, detail.timeline, detail.checks_performed,
            detail.checks_unavailable, detail.sources_attempted, detail.checks_finding_counts, tz_name=tz_name,
        )
    )
