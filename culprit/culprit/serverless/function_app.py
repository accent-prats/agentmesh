"""Entry point for the Culprit Durable Functions app - registers the
orchestrator/activity Blueprints (`orchestrators.py`, `activities.py`)
and defines every trigger binding, one per existing TriggerMode:

- `scheduled_cycle_timer` (Timer) - the primary deliverable per
  management's "mostly scheduled, unattended" requirement: fires on
  `CULPRIT_SCHEDULE_CRON`, reads `scope_name`/`window_hours` from the DB
  at fire time (same live-editable-without-redeploy behavior as today's
  `scheduler/cron.py::scheduled_cycle`) - only the cron expression itself
  needs an app-setting change (+ a Function App restart, not a full
  redeploy) rather than a live DB edit; see this package's README for why
  that one piece doesn't carry over 1:1.
- `pre_flight_timer` (Timer, hourly) - calls `pre_flight_scan_activity`
  directly, no orchestration - kept deliberately simple per the
  proposal's own scope decision.
- `trigger_live_run_http` (HTTP) - the ad hoc / chat trigger's
  replacement; starts an orchestration and returns Durable Functions'
  standard check-status response so a caller can poll completion.
- `event_grid_trigger` (Event Grid) - the event-driven trigger's
  replacement. Azure Functions' native Event Grid binding handles the
  subscription-validation handshake itself, so - unlike today's manual
  webhook receiver (`scheduler/events.py`) - there is no handshake code
  to write here at all.
- `get_azure_settings_http`/`put_azure_settings_http` (HTTP) - a stand-in
  for the Settings screen's own Azure tab (api/routes_settings.py's
  `GET`/`PUT /settings/azure`), which this deployment has no way to reach
  otherwise - the Console/Settings web UI was explicitly scoped out of
  this migration (the proposal's own "Phase 3", not part of this core
  deliverable). Found live 2026-11-23: discover_run_activity's own
  `{"skip": "no_subscription_configured"}` branch fired on a real run,
  and the obvious fix - "just configure it on the Settings page" - landed
  on the wrong database entirely: the existing Docker Compose deployment
  reads from its own local `sqlite:////app/data/culprit.db` (config.py's
  CULPRIT_DATABASE_URL default), completely separate from this Function
  App's own Postgres database - configuring one has zero effect on the
  other. These two routes call the exact same repository functions
  (`save_azure_settings`/`azure_settings_view`) the real Settings API
  already uses, just reachable here until the real Console/Settings UI
  gets its own serverless home. Routed at `settings/azure`, NOT
  `admin/settings/azure` - the Azure Functions host itself reserves the
  entire `admin/*` route prefix for its own built-in management API
  (`admin/host/status`, `admin/functions/{name}`, etc.); a first attempt
  at `admin/settings/azure` loaded with both functions showing
  "is in error: The specified route conflicts with one or more built in
  routes" in Application Insights - this prefix is reserved host-wide,
  regardless of `routePrefix` config, so no user HTTP trigger can ever
  use it.
"""
from __future__ import annotations

import logging

import azure.durable_functions as df
import azure.functions as func

from culprit.serverless import activities, orchestrators

log = logging.getLogger(__name__)

app = df.DFApp(http_auth_level=func.AuthLevel.FUNCTION)
app.register_functions(activities.bp)
app.register_functions(orchestrators.bp)


@app.timer_trigger(schedule="%CULPRIT_SCHEDULE_CRON%", arg_name="timer", run_on_startup=False, use_monitor=True)
@app.durable_client_input(client_name="client")
async def scheduled_cycle_timer(timer: func.TimerRequest, client) -> None:
    from culprit.api import deps
    from culprit.db import repository

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        cfg = repository.load_schedule_settings(session)

    if not cfg.enabled:
        log.info("Scheduled cycle fired but is disabled on /culprit/settings - skipping")
        return

    instance_id = await client.start_new(
        "pipeline_orchestrator",
        client_input={
            "scope_name": cfg.scope_name,
            "window_hours": cfg.window_hours,
            "trigger_mode": "scheduled",
            "maintenance_configuration_id": "Not tied to a maintenance schedule",
        },
    )
    log.info("Scheduled cycle started orchestration %s (scope=%s)", instance_id, cfg.scope_name)


@app.timer_trigger(schedule="0 0 * * * *", arg_name="timer", run_on_startup=False, use_monitor=True)
def pre_flight_timer(timer: func.TimerRequest) -> None:
    result = activities.run_pre_flight_scan({})
    log.info("Pre-flight scan: %s", result)


@app.route(route="runs/live", methods=["POST"])
@app.durable_client_input(client_name="client")
async def trigger_live_run_http(req: func.HttpRequest, client) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        body = {}

    instance_id = await client.start_new(
        "pipeline_orchestrator",
        client_input={
            "scope_name": body.get("scope_name", "ad-hoc"),
            "window_hours": body.get("window_hours", 24),
            "trigger_mode": "ad_hoc",
            "maintenance_configuration_id": body.get("maintenance_configuration_id", "Not tied to a maintenance schedule"),
        },
    )
    log.info("Ad hoc trigger started orchestration %s", instance_id)
    return client.create_check_status_response(req, instance_id)


@app.route(route="settings/azure", methods=["GET"])
def get_azure_settings_http(req: func.HttpRequest) -> func.HttpResponse:
    """Stand-in for `GET /settings/azure` - see module docstring for why
    this exists at all. Returns the exact same AzureSettingsView shape
    the real Settings screen reads, so a caller can confirm what actually
    landed in THIS deployment's own database."""
    from culprit.api import deps
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        view = repository.azure_settings_view(session)

    return func.HttpResponse(
        view.model_dump_json(),
        status_code=200,
        headers={"Content-Type": "application/json"},
    )


@app.route(route="settings/azure", methods=["PUT"])
def put_azure_settings_http(req: func.HttpRequest) -> func.HttpResponse:
    """Stand-in for `PUT /settings/azure` - see module docstring. Body is
    the same AzureSettingsInput shape the real Settings form submits:
    {"subscription_ids": [...], "log_analytics_workspace_id": "...",
    "tenant_id": "...", "client_id": "...", "client_secret": "...",
    "clear_credentials": false} - every field optional, same
    leave-alone-if-blank rules as the real form (see
    repository.py::save_azure_settings's own docstring)."""
    import json

    from culprit.api import deps
    from culprit.db import repository
    from culprit.models.settings import AzureSettingsInput

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "request body must be JSON"}),
            status_code=400,
            headers={"Content-Type": "application/json"},
        )

    cfg = AzureSettingsInput(**body)
    with deps.get_session_factory()() as session:
        repository.save_azure_settings(session, cfg)
        view = repository.azure_settings_view(session)

    return func.HttpResponse(
        view.model_dump_json(),
        status_code=200,
        headers={"Content-Type": "application/json"},
    )


@app.event_grid_trigger(arg_name="event")
@app.durable_client_input(client_name="client")
async def event_grid_trigger(event: func.EventGridEvent, client) -> None:
    data = event.get_json()
    run_ref = data.get("run_id") or data.get("correlationId") or event.id

    instance_id = await client.start_new(
        "pipeline_orchestrator",
        client_input={
            "scope_name": str(run_ref),
            "window_hours": 24,
            "trigger_mode": "event_driven",
            "maintenance_configuration_id": "Not tied to a maintenance schedule",
        },
    )
    log.info("Event-driven trigger (ref=%s) started orchestration %s", run_ref, instance_id)
