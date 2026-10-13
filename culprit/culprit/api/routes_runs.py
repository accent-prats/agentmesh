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
from culprit.api.root_path_middleware import root_path
from culprit.config import settings
from culprit.models.report import FleetReport

log = logging.getLogger(__name__)

_DECRYPT_ERROR_DETAIL = (
    "Stored Azure settings could not be decrypted - CULPRIT_ENCRYPTION_KEY likely changed "
    "since they were saved. Re-enter them on /culprit/settings."
)

router = APIRouter(prefix="/runs", tags=["runs"])


class LiveRunRequest(BaseModel):
    window_hours: int = Field(default=24, ge=1, le=720)
    scope_name: str = "live"


def _report_url(request: Request, run_id: str) -> str:
    """Absolute link back to this run's rendered report, reverse-proxy
    prefix included - what the Teams/Slack digest's "Open full report"
    button links to (culprit/reporting/notify.py)."""
    return f"{str(request.base_url).rstrip('/')}{root_path(request)}/runs/{run_id}/report.html"


def _notify_if_configured(report: FleetReport, request: Request) -> None:
    """Push the digest to whichever webhook is configured (proposal
    Section 10: "delivery meets people where they already are"). Best-
    effort - a webhook outage must never fail the run that already
    completed successfully, so any error here is logged and swallowed."""
    webhook = settings.teams_webhook_url or settings.slack_webhook_url
    if not webhook:
        return
    try:
        from culprit.reporting.notify import post_to_slack, post_to_teams

        poster = post_to_teams if settings.teams_webhook_url else post_to_slack
        response = poster(webhook, report, report_url=_report_url(request, report.run.run_id))
        log.info("Posted digest for run %s to webhook - status %s", report.run.run_id, response.status_code)
    except Exception:  # noqa: BLE001 - a notification failure must not fail the run
        log.exception("Failed to post digest for run %s to webhook", report.run.run_id)


@router.post("/demo", response_model=FleetReport)
def trigger_demo_run(request: Request) -> FleetReport:
    from culprit import config as config_module
    from culprit.db import repository
    from culprit.demo.generate_scenario import TOTAL_MACHINES, build_scenario
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
        raise HTTPException(status_code=502, detail=f"Live run failed: {exc}") from exc

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
    from culprit.reporting.render import render_fleet_report_html

    with deps.get_session_factory()() as session:
        report = repository.load_fleet_report(session, run_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return HTMLResponse(render_fleet_report_html(report))


@router.get("/{run_id}/machines/{vm_name}.html")
def get_machine_html(run_id: str, vm_name: str):
    """The report's third altitude (proposal Section 8) - one machine's
    own deviation from its cluster's representative member."""
    from fastapi.responses import HTMLResponse

    from culprit.db import repository
    from culprit.reporting.render import render_machine_html

    with deps.get_session_factory()() as session:
        detail = repository.get_machine_detail(session, run_id, vm_name)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Machine {vm_name} not found in run {run_id}")
    cluster, member, result, outcome, collection_gaps = detail
    return HTMLResponse(render_machine_html(cluster, member, result, outcome, collection_gaps))
