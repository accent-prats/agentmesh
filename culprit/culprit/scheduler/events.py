"""Event-driven trigger receiver (proposal Section 10).

Handles the real Event Grid subscription-validation handshake (documented,
stable Event Grid behavior: on subscription creation Event Grid POSTs a
`Microsoft.EventGrid.SubscriptionValidationEvent` and the endpoint must
echo back `data.validationCode` in a `validationResponse` field, or the
subscription is never activated).

Honest caveat on the event *source*: Azure Update Manager does not
publish a documented, stable Event Grid system topic for "maintenance run
completed" as of this writing. The two realistic wiring options for Phase
1c are (a) an Azure Monitor Action Group webhook attached to an Activity
Log alert on `Microsoft.Maintenance/applyUpdates` completion, or (b) a
small Function/Logic App that polls Resource Graph's
`maintenanceresources` table and posts to this endpoint once a run's
status leaves "InProgress". Either way, this receiver's contract is the
same: accept a payload naming a `run_id` (or enough to look one up) and
kick off collection for it. Wire whichever source your environment
actually supports here - this module deliberately doesn't hardcode one.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request

log = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["events"])


@router.post("/event-grid")
async def event_grid_webhook(request: Request, background_tasks: BackgroundTasks) -> Any:
    body = await request.json()
    events = body if isinstance(body, list) else [body]

    for event in events:
        event_type = event.get("eventType") or event.get("type")  # Event Grid schema vs. CloudEvents schema
        if event_type == "Microsoft.EventGrid.SubscriptionValidationEvent":
            validation_code = event["data"]["validationCode"]
            log.info("Event Grid subscription validation handshake completed")
            return {"validationResponse": validation_code}

        # Event Grid expects a fast response and will retry on a timeout -
        # a full discover/collect/diagnose cycle is far too slow to run
        # inline, so it's dispatched to run after this response is sent.
        background_tasks.add_task(_handle_maintenance_event, event)

    return {"ok": True}


def _handle_maintenance_event(event: dict) -> None:
    """Dispatches the same discover -> collect -> diagnose path
    `scheduler/cron.py::scheduled_cycle` and `POST /runs/live` use
    (culprit/pipeline/live_run.py) - whichever of the two sourcing options
    in this module's docstring actually fired this webhook, the downstream
    action is identical: go find what's currently failed and diagnose it.
    The event's own identifiers (whatever this environment's source puts
    there) are used only for the run's scope_name/logging, not to resolve
    a specific maintenanceResources row - Update Manager has no documented
    Event Grid schema to resolve one from, per this module's own docstring."""
    from culprit.models.patch_run import TriggerMode
    from culprit.pipeline.live_run import NoSubscriptionConfigured, execute_live_run

    data = event.get("data", {})
    run_ref = data.get("run_id") or data.get("correlationId") or data.get("id") or "event-driven"
    log.info("Event-driven trigger received (ref=%s) - dispatching collection", run_ref)

    try:
        report = execute_live_run(window_hours=24, scope_name=str(run_ref), trigger_mode=TriggerMode.EVENT_DRIVEN)
    except NoSubscriptionConfigured:
        log.info("Event-driven trigger skipped - no Azure subscription configured on /culprit/settings yet")
        return
    except Exception:  # noqa: BLE001 - one bad webhook payload must not crash request handling
        log.exception("Event-driven trigger failed (ref=%s)", run_ref)
        return

    log.info(
        "Event-driven cycle complete (ref=%s): %d/%d failed, %d distinct causes",
        run_ref, report.total_failed, report.total_machines, report.total_clusters,
    )
