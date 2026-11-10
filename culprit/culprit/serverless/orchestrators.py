"""The two Durable Functions orchestrators that replace `pipeline/
live_run.py::execute_live_run` + `pipeline/orchestrator.py::Pipeline.run`'s
single in-process call chain.

Orchestrator code must be deterministic (the Durable Functions runtime
replays it from history on every await) - no direct `datetime.now()`,
no I/O, no randomness in this file. Every non-deterministic step (the
actual window computation, any Azure/LLM/DB call) lives in an activity
in `activities.py`; this file only sequences activity calls and does
plain, deterministic data shuffling (partitioning `bundles` by vm_id,
building each cluster's own input dict) between them.

`pipeline_orchestrator` is the top-level entry point, started by every
trigger in `function_app.py` (timer, HTTP, Event Grid). `diagnose_cluster_
orchestrator` is a *sub-orchestration*, fanned out once per cluster -
it exists as its own orchestrator, not a single activity, because the
real per-cluster flow (`Pipeline._diagnose_one`) is conditional and
multi-step (rule engine -> maybe deep RCA -> maybe recollect -> maybe
re-diagnose -> advise+persist), and an activity function cannot itself
call another activity - only an orchestrator (or sub-orchestrator) can.
"""
from __future__ import annotations

import azure.durable_functions as df

bp = df.Blueprint()


def pipeline_orchestrator_generator(context: df.DurableOrchestrationContext):
    """The actual orchestrator logic, as a plain undecorated generator
    function - tests drive this directly. `@bp.orchestration_trigger`
    (below) wraps a function in a `FunctionBuilder` with no supported way
    to call the original generator back out of it (confirmed against the
    installed `azure-functions-durable` package, same finding as
    activities.py's `run_pre_flight_scan`), so the function meant to be
    unit-tested has to stay undecorated and registration has to be a
    separate, thin wrapper."""
    input_ = context.get_input()

    discovery = yield context.call_activity("discover_run_activity", input_)
    if discovery.get("skip"):
        return {"skipped": discovery["skip"]}

    run = discovery["run"]
    machines = discovery["machines"]
    window_start = discovery["window_start"]
    window_end = discovery["window_end"]

    if machines:
        collect_tasks = [
            context.call_activity(
                "collect_machine_activity",
                {
                    "run_id": run["run_id"], "machine": machine,
                    "window_start": window_start, "window_end": window_end,
                },
            )
            for machine in machines
        ]
        bundles = yield context.task_all(collect_tasks)
    else:
        bundles = []

    cluster_result = yield context.call_activity(
        "cluster_and_checkpoint_activity", {"run": run, "bundles": bundles},
    )
    clusters = cluster_result["clusters"]
    history = cluster_result["history"]

    if clusters:
        bundle_by_vm_id = {b["machine"]["vm_id"]: b for b in bundles}
        diagnose_tasks = [
            context.call_sub_orchestrator(
                "diagnose_cluster_orchestrator",
                {
                    "run_id": run["run_id"],
                    "cluster": cluster,
                    "member_bundles": [bundle_by_vm_id[m["vm_id"]] for m in cluster["members"]],
                    "history": history,
                    "window_start": window_start,
                    "window_end": window_end,
                },
            )
            for cluster in clusters
        ]
        yield context.task_all(diagnose_tasks)

    finalized = yield context.call_activity(
        "finalize_run_activity",
        {
            "run": run, "bundles": bundles, "window_start": window_start,
            "window_end": window_end, "total_machines": discovery["total_machines"],
        },
    )

    yield context.call_activity(
        "notify_activity", {"run_id": run["run_id"], "trigger_mode": run["trigger_mode"]},
    )

    return {
        "run_id": run["run_id"],
        "total_failed": finalized["total_failed"],
        "total_clusters": finalized["total_clusters"],
    }


def diagnose_cluster_orchestrator_generator(context: df.DurableOrchestrationContext):
    """Same reasoning as `pipeline_orchestrator_generator` above - the
    plain, directly testable form of this sub-orchestration."""
    input_ = context.get_input()

    result = yield context.call_activity("evaluate_rules_activity", input_)

    if result is None:
        # near_misses/retrieval_context are computed ONCE, against the
        # pre-recollection representative, and reused verbatim for every
        # deep_rca_activity call below - matching `Pipeline._diagnose_one`
        # exactly (it computes both once and reuses them for the post-
        # recollection re-diagnosis call too, never recomputing against
        # the recollected bundle). Found in review 2026-11-10: an earlier
        # version let deep_rca_activity recompute both fresh on every
        # call, which silently fed the recollected bundle's near-miss
        # flags into the second call instead of the original's - a real
        # fidelity gap from the Docker deployment, not a style issue.
        rca_context = yield context.call_activity("compute_rca_context_activity", input_)
        deep_rca_input = {
            **input_, "near_misses": rca_context["near_misses"], "retrieval_context": rca_context["retrieval_context"],
        }
        result = yield context.call_activity("deep_rca_activity", deep_rca_input)

        if result.get("missing_evidence"):
            representative = next(
                b for b in input_["member_bundles"] if b["machine"]["vm_id"] == input_["cluster"]["representative_vm_id"]
            )
            recollected = yield context.call_activity(
                "recollect_activity",
                {
                    "run_id": input_["run_id"],
                    "representative_bundle": representative,
                    "missing_evidence": result["missing_evidence"],
                    "window_start": input_["window_start"],
                    "window_end": input_["window_end"],
                },
            )
            if recollected.get("changed"):
                result = yield context.call_activity(
                    "deep_rca_activity",
                    {**deep_rca_input, "representative_bundle": recollected["bundle"]},
                )
                # The recollected bundle replaces its entry in member_bundles
                # before persistence, so save_machine_outcomes persists the
                # augmented evidence for the representative, not the
                # pre-recollection copy - the same bug `pipeline/orchestrator.
                # py::Pipeline.run`'s own docstring documents fixing in the
                # Docker deployment (found 2026-10-19); this sub-orchestration
                # must not reintroduce it.
                input_ = {
                    **input_,
                    "member_bundles": [
                        recollected["bundle"] if b["machine"]["vm_id"] == input_["cluster"]["representative_vm_id"] else b
                        for b in input_["member_bundles"]
                    ],
                }

    return (yield context.call_activity(
        "advise_and_persist_activity",
        {
            "run_id": input_["run_id"], "cluster": input_["cluster"],
            "member_bundles": input_["member_bundles"], "result": result, "history": input_["history"],
        },
    ))


@bp.orchestration_trigger(context_name="context")
def pipeline_orchestrator(context: df.DurableOrchestrationContext):
    return (yield from pipeline_orchestrator_generator(context))


@bp.orchestration_trigger(context_name="context")
def diagnose_cluster_orchestrator(context: df.DurableOrchestrationContext):
    return (yield from diagnose_cluster_orchestrator_generator(context))
