"""Durable Functions activities - each one a thin wrapper calling straight
into the existing, already-tested pipeline modules. Registered on a
`df.Blueprint()` (not the main `FunctionApp`) so `function_app.py` can
`app.register_functions(bp)` - the documented pattern for splitting a
Durable Functions app across files.

Every activity takes and returns plain JSON-serializable dicts (Durable
Functions requirement) - `serialization.py` holds the handful of
(de)serializers needed for that. Window timestamps cross the boundary as
ISO 8601 strings, not datetimes.

What this does NOT change: `pipeline/live_run.py::execute_live_run` and
`pipeline/orchestrator.py::Pipeline.run` are untouched and still drive the
existing Docker deployment exactly as before. This module re-implements
their same sequence as discrete, independently callable steps - it cannot
simply call those functions (they're each one monolithic call, which is
exactly the shape that has to be decomposed for fan-out/checkpointing) -
but every individual step below calls the same underlying pipeline
functions those two do, in the same order, with the same persistence
side effects.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import azure.durable_functions as df

from culprit.models.evidence import EvidenceBundle
from culprit.serverless.serialization import (
    bundle_from_dict,
    bundle_to_dict,
    cluster_from_dict,
    cluster_to_dict,
    machine_from_dict,
    patch_run_from_dict,
    patch_run_to_dict,
    rca_result_from_dict,
    rca_result_to_dict,
)

log = logging.getLogger(__name__)

bp = df.Blueprint()


def _find_representative(cluster, member_bundle_dicts: list[dict]) -> EvidenceBundle:
    for d in member_bundle_dicts:
        if d["machine"]["vm_id"] == cluster.representative_vm_id:
            return bundle_from_dict(d)
    raise ValueError(
        f"representative {cluster.representative_vm_id} not found in the member bundles given to "
        f"cluster {cluster.cluster_id} - this activity was called with an incomplete member_bundles list"
    )


@bp.activity_trigger(input_name="input_")
def discover_run_activity(input_: dict) -> dict:
    """Same first half of `execute_live_run` (window computation, Azure
    settings/credential resolution, failed-machine discovery, total-fleet
    count, PatchRun construction) - returns `{"skip": "..."}`, never
    raises, when no Azure subscription is configured, matching
    `scheduler/cron.py::scheduled_cycle`'s own "skip quietly" contract
    for the scheduled/event-driven triggers (NoSubscriptionConfigured
    was always caught and logged there, never allowed to crash the
    caller)."""
    from culprit.api import deps
    from culprit.db import repository
    from culprit.models.patch_run import PatchRun, TriggerMode
    from culprit.pipeline.discovery import count_total_machines, discover_failed_machines

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        azure_cfg = repository.load_azure_settings(session)
    if not azure_cfg.subscription_ids:
        return {"skip": "no_subscription_configured"}

    with session_factory() as session:
        _collectors, azure_cfg, credential = deps.build_live_collectors(session)

    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(hours=input_["window_hours"])

    machines = discover_failed_machines(credential, azure_cfg.subscription_ids, window_start, window_end)
    total_machines = count_total_machines(credential, azure_cfg.subscription_ids)

    run = PatchRun(
        run_id=f"live-{window_end.strftime('%Y%m%d-%H%M%S')}",
        maintenance_configuration_id=input_.get("maintenance_configuration_id", "Not tied to a maintenance schedule"),
        subscription_id=azure_cfg.subscription_ids[0],
        scope_name=input_["scope_name"],
        started_at=window_start,
        ended_at=window_end,
        total_machines=total_machines,
        trigger_mode=TriggerMode(input_["trigger_mode"]),
    )

    return {
        "run": patch_run_to_dict(run),
        "machines": [m.model_dump(mode="json") for m in machines],
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "total_machines": total_machines,
    }


@bp.activity_trigger(input_name="input_")
def collect_machine_activity(input_: dict) -> dict:
    """One machine's full evidence collection - the fan-out unit that
    replaces `collection.py::collect_all`'s in-process ThreadPoolExecutor
    with Durable Functions' own fan-out, calling the exact same
    `collect_one_machine` the thread-pool path calls."""
    from culprit.api import deps
    from culprit.pipeline.collection import collect_one_machine

    machine = machine_from_dict(input_["machine"])
    window_start = datetime.fromisoformat(input_["window_start"])
    window_end = datetime.fromisoformat(input_["window_end"])

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        collectors, _azure_cfg, _credential = deps.build_live_collectors(session)

    bundle = collect_one_machine(input_["run_id"], machine, collectors, window_start, window_end)
    return bundle_to_dict(bundle)


@bp.activity_trigger(input_name="input_")
def cluster_and_checkpoint_activity(input_: dict) -> dict:
    """`Pipeline.run()`'s own opening section: save the run (STARTED),
    fingerprint/cluster every bundle, checkpoint each cluster and the
    run's own stage to CLUSTERED, then load repeat-offender history -
    exactly the same persisted checkpoints the Docker deployment leaves,
    so a crash here is recoverable the same way."""
    from culprit.api import deps
    from culprit.db import repository
    from culprit.db.models import RunStage
    from culprit.pipeline.fingerprint import cluster_run

    run = patch_run_from_dict(input_["run"])
    bundles = [bundle_from_dict(b) for b in input_["bundles"]]

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        repository.save_run(session, run, stage=RunStage.STARTED)
        clusters = cluster_run(run.run_id, bundles)
        for cluster in clusters:
            repository.save_cluster(session, cluster)
        repository.update_run_stage(session, run.run_id, RunStage.CLUSTERED)
        history = repository.historical_cluster_keys(session, run.run_id)

    return {"clusters": [cluster_to_dict(c) for c in clusters], "history": history}


@bp.activity_trigger(input_name="input_")
def evaluate_rules_activity(input_: dict) -> dict | None:
    """The rule engine's half of `Pipeline._diagnose_one` - a cluster
    that settles here never reaches an LLM call at all, same as today."""
    from culprit.pipeline.rules import evaluate_rules

    cluster = cluster_from_dict(input_["cluster"])
    representative = _find_representative(cluster, input_["member_bundles"])
    result = evaluate_rules(cluster, representative)
    return rca_result_to_dict(result) if result is not None else None


@bp.activity_trigger(input_name="input_")
def compute_rca_context_activity(input_: dict) -> dict:
    """Computes `near_misses`/`retrieval_context` exactly once, against
    the PRE-recollection representative - split out as its own activity
    (found in review 2026-11-10) because `_diagnose_one` computes these
    once and reuses them verbatim for both the first AND the post-
    recollection re-diagnosis call. An earlier version of this port had
    `deep_rca_activity` recompute both values fresh on every call,
    which silently used the RECOLLECTED bundle's near-miss flags for the
    second call instead of the original's - a real fidelity gap from the
    Docker deployment, not just a style difference, since recollection
    specifically targets the evidence `_describe_near_misses` inspects
    (disk_low/lock_held). This activity's result is computed once by the
    orchestrator and threaded into every `deep_rca_activity` call for
    this cluster, never recomputed."""
    from culprit.api import deps
    from culprit.pipeline.orchestrator import _describe_near_misses

    cluster = cluster_from_dict(input_["cluster"])
    representative = _find_representative(cluster, input_["member_bundles"])

    retrieval_store = deps.get_retrieval_store()
    near_misses = _describe_near_misses(cluster, representative)
    query = f"{cluster.fingerprint.error_code_normalized} {cluster.fingerprint.failing_target} {cluster.fingerprint.os_family.value}"
    retrieval_context = retrieval_store.render_context(query) if retrieval_store else ""

    return {"near_misses": near_misses, "retrieval_context": retrieval_context}


@bp.activity_trigger(input_name="input_")
def deep_rca_activity(input_: dict) -> dict:
    """The deep-RCA half of `Pipeline._diagnose_one`. `near_misses`/
    `retrieval_context` are always given (computed once by
    `compute_rca_context_activity`, see its own docstring for why) -
    this activity never recomputes them itself. Called a second time,
    with `representative_bundle` set to the recollected bundle, after
    `recollect_activity` finds new evidence - the same "re-diagnose
    once" shape `_diagnose_one` already has, reusing the SAME
    `near_misses`/`retrieval_context` both times, matching
    `_diagnose_one` exactly."""
    from culprit.api import deps

    cluster = cluster_from_dict(input_["cluster"])
    representative = (
        bundle_from_dict(input_["representative_bundle"])
        if input_.get("representative_bundle")
        else _find_representative(cluster, input_["member_bundles"])
    )

    rca_agent = deps.get_rca_agent()
    result = rca_agent.diagnose(cluster, representative, input_["near_misses"], input_["retrieval_context"])
    return rca_result_to_dict(result)


@bp.activity_trigger(input_name="input_")
def recollect_activity(input_: dict) -> dict:
    """The targeted re-collection pass `_diagnose_one` runs when the RCA
    agent names `missing_evidence` - same `recollect_targeted` +
    `merge_recollection` the Docker deployment uses, with a fresh
    `collectors`/credential built in-activity (never passed across the
    activity boundary - Azure SDK clients and credentials aren't JSON-
    serializable, and `build_live_collectors` is cheap/stateless enough
    that rebuilding it per activity call is the correct Durable Functions
    pattern, not a shortcut)."""
    from culprit.api import deps
    from culprit.pipeline.collection import recollect_targeted
    from culprit.pipeline.normalize import merge_recollection

    representative = bundle_from_dict(input_["representative_bundle"])
    window_start = datetime.fromisoformat(input_["window_start"])
    window_end = datetime.fromisoformat(input_["window_end"])

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        collectors, _azure_cfg, _credential = deps.build_live_collectors(session)

    new_results = recollect_targeted(
        input_["run_id"], representative.machine, input_["missing_evidence"], collectors, window_start, window_end,
    )
    if not new_results:
        return {"changed": False}
    updated = merge_recollection(representative, new_results)
    return {"changed": True, "bundle": bundle_to_dict(updated)}


@bp.activity_trigger(input_name="input_")
def advise_and_persist_activity(input_: dict) -> dict:
    """The closing section of `Pipeline.run()`'s per-cluster loop: advise
    (recurrence + automation-safety), then persist the RCAResult and
    every member machine's outcome - the same two `repository` calls the
    Docker deployment makes, in the same order, inside one DB session."""
    from culprit.api import deps
    from culprit.db import repository
    from culprit.pipeline.advisor import advise

    cluster = cluster_from_dict(input_["cluster"])
    result = rca_result_from_dict(input_["result"])
    member_bundles = [bundle_from_dict(b) for b in input_["member_bundles"]]

    result, recurrence = advise(result, cluster.cluster_key, input_["history"])

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        repository.save_rca_result(session, result, consecutive_cycles=recurrence.consecutive_cycles)
        repository.save_machine_outcomes(session, input_["run_id"], cluster.cluster_key, member_bundles)

    return {
        "cluster_id": cluster.cluster_id,
        "result": rca_result_to_dict(result),
        "recurrence_badge": recurrence.badge,
        "consecutive_cycles": recurrence.consecutive_cycles,
    }


@bp.activity_trigger(input_name="input_")
def finalize_run_activity(input_: dict) -> dict:
    """`execute_live_run`'s closing section: mark the run COMPLETE, load
    the persisted FleetReport, then best-effort build + save the
    Installation Report - same try/except-and-log-only discipline as the
    original (a failure here must never fail a run whose actual RCA
    already completed and persisted successfully)."""
    from culprit.api import deps
    from culprit.db import repository
    from culprit.db.models import RunStage
    from culprit.pipeline.discovery import discover_all_patch_outcomes_with_identity
    from culprit.pipeline.installation_report import build_installation_report

    run = patch_run_from_dict(input_["run"])
    bundles = [bundle_from_dict(b) for b in input_["bundles"]]
    window_start = datetime.fromisoformat(input_["window_start"])
    window_end = datetime.fromisoformat(input_["window_end"])

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        repository.update_run_stage(
            session, run.run_id, RunStage.COMPLETE,
            ended_at=datetime.now(timezone.utc), failed_machines=len(bundles),
        )
        fleet_report = repository.load_fleet_report(session, run.run_id)

    try:
        with session_factory() as session:
            _collectors, azure_cfg, credential = deps.build_live_collectors(session)
        all_outcomes = discover_all_patch_outcomes_with_identity(
            credential, azure_cfg.subscription_ids, window_start, window_end,
        )
        excluded_count = max(0, input_["total_machines"] - len(all_outcomes))
        installation_report = build_installation_report(run, bundles, fleet_report, all_outcomes, excluded_count)
        with session_factory() as session:
            repository.save_installation_report(
                session, run.run_id, installation_report.rows, installation_report.excluded_count,
            )
    except Exception:  # noqa: BLE001 - must not fail a run whose RCA already completed successfully
        log.exception("Failed to build the Patch Installation Report for run %s", run.run_id)

    return {
        "run_id": run.run_id,
        "total_failed": fleet_report.total_failed,
        "total_clusters": fleet_report.total_clusters,
    }


@bp.activity_trigger(input_name="input_")
def notify_activity(input_: dict) -> dict:
    """`execute_live_run`'s auto-email step - `send_report_on_completion`
    is already fully best-effort/non-raising internally; this try/except
    is belt-and-braces, matching the original's own double-layer
    convention."""
    from culprit.api import deps
    from culprit.db import repository
    from culprit.models.patch_run import TriggerMode
    from culprit.notifications.auto_report_email import send_report_on_completion

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        fleet_report = repository.load_fleet_report(session, input_["run_id"])

    try:
        send_report_on_completion(session_factory, fleet_report, TriggerMode(input_["trigger_mode"]))
    except Exception:  # noqa: BLE001 - must not fail a run that already completed successfully
        log.exception("Failed to auto-send the report email for run %s", input_["run_id"])

    return {"notified": True}


def run_pre_flight_scan(input_: dict) -> dict:
    """The hourly pre-flight scan's actual logic - a plain, undecorated
    function (not a Durable activity) so `function_app.py`'s simple timer
    trigger can call it directly in-process. Kept deliberately simple, no
    orchestrator, no fan-out, per the proposal's own scope decision:
    management's primary ask is the scheduled discover/collect/diagnose/
    notify path above, not this secondary prediction feature. Calls the
    exact same `pipeline/preflight.py::run_preflight_scan` the Docker
    deployment's `scheduler/cron.py::pre_flight_check` already uses.

    Deliberately NOT a `@bp.activity_trigger` - the Durable Functions SDK
    wraps a decorated function in a `FunctionBuilder` with no supported
    way to call the original function back out of it directly (confirmed
    against the installed `azure-functions-durable` package, not assumed),
    so a function meant to be called directly in-process must stay
    undecorated."""
    from culprit.api import deps
    from culprit.db import repository
    from culprit.pipeline.discovery import discover_all_machines
    from culprit.pipeline.preflight import run_preflight_scan

    session_factory = deps.get_session_factory()
    with session_factory() as session:
        azure_cfg = repository.load_azure_settings(session)
    if not azure_cfg.subscription_ids:
        return {"skip": "no_subscription_configured"}

    with session_factory() as session:
        collectors, azure_cfg, credential = deps.build_live_collectors(session)
    machines = discover_all_machines(credential, azure_cfg.subscription_ids)
    findings = run_preflight_scan(collectors, machines)

    with session_factory() as session:
        repository.save_preflight_findings(session, findings)

    return {"flagged": len(findings), "total": len(machines)}
