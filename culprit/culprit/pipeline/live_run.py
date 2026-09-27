"""Shared live-run execution: real Azure discovery + collection +
Pipeline.run(), the one call path every non-demo trigger uses (proposal
Section 10) - `POST /runs/live` (ad hoc), `scheduler/cron.py::scheduled_cycle`
(scheduled), and `scheduler/events.py`'s Event Grid handler (event-driven)
all just supply a different TriggerMode and call `execute_live_run`.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from culprit.models.patch_run import PatchRun, TriggerMode


class NoSubscriptionConfigured(Exception):
    """No Azure subscription is configured on /culprit/settings yet -
    raised before anything Azure-SDK-shaped is touched, so this is a clean
    "not configured" signal even in a deployment without the optional
    `culprit[azure]` extra installed at all."""


def execute_live_run(
    *,
    window_hours: int,
    scope_name: str,
    trigger_mode: TriggerMode,
    maintenance_configuration_id: str = "(live discovery - not tied to one maintenanceConfigurations run)",
):
    """Discovers every machine with a non-succeeded patch result in the
    window, collects real evidence for each, and diagnoses it exactly
    like the demo scenario does for synthetic data - the only difference
    is where the EvidenceBundles come from. Returns the persisted
    FleetReport (with trend attached, same as every other report read)."""
    from culprit.api import deps
    from culprit.db import repository
    from culprit.pipeline.collection import collect_all, recollect_targeted
    from culprit.pipeline.discovery import count_total_machines, discover_failed_machines
    from culprit.pipeline.orchestrator import Pipeline

    session_factory = deps.get_session_factory()

    with session_factory() as session:
        azure_cfg = repository.load_azure_settings(session)
    if not azure_cfg.subscription_ids:
        raise NoSubscriptionConfigured("No Azure subscription configured - set it on /culprit/settings first.")

    # May raise ImportError (azure-identity not installed) or InvalidToken
    # (CULPRIT_ENCRYPTION_KEY rotated since settings were saved) - both are
    # deliberately left uncaught here for the caller to translate into
    # whatever's appropriate for its own context (an HTTP error for the API
    # route, a logged skip for the scheduler).
    with session_factory() as session:
        collectors, azure_cfg, credential = deps.build_live_collectors(session)

    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(hours=window_hours)

    machines = discover_failed_machines(credential, azure_cfg.subscription_ids, window_start, window_end)
    total_machines = count_total_machines(credential, azure_cfg.subscription_ids)

    run = PatchRun(
        run_id=f"live-{window_end.strftime('%Y%m%d-%H%M%S')}",
        maintenance_configuration_id=maintenance_configuration_id,
        subscription_id=azure_cfg.subscription_ids[0],
        scope_name=scope_name,
        started_at=window_start,
        ended_at=window_end,
        total_machines=total_machines,
        trigger_mode=trigger_mode,
    )

    bundles = collect_all(run.run_id, machines, collectors, window_start, window_end) if machines else []

    def recollect_fn(bundle, missing_evidence):
        return recollect_targeted(run.run_id, bundle.machine, missing_evidence, collectors, window_start, window_end)

    pipeline = Pipeline(
        session_factory=session_factory,
        rca_agent=deps.get_rca_agent(),
        retrieval_store=deps.get_retrieval_store(),
        recollect_fn=recollect_fn,
    )
    output = pipeline.run(run, bundles)

    with session_factory() as session:
        return repository.load_fleet_report(session, output.run.run_id)
