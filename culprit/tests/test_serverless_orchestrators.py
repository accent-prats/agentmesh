"""culprit/serverless/orchestrators.py - driven directly as plain Python
generators (Microsoft's own documented pattern for unit-testing Durable
Functions orchestrators: no live Functions host, no Azure Storage
emulator - an orchestrator function is deterministic, side-effect-free
Python that only ever *yields* activity/sub-orchestrator calls, so a fake
context that records what was yielded and lets the test `.send()` back
whatever result it wants to simulate is a complete, faithful test double).

These tests exist to verify the NEW control-flow code in orchestrators.py
itself - the activities it calls are already covered by the existing
pipeline test suite (they're thin wrappers around already-tested
functions); what's genuinely new and unverified without these tests is
the sequencing: which activity is called when, with what input, and -
most importantly - that a cluster's own recollected representative bundle
actually reaches persistence rather than the stale pre-recollection copy
(the exact bug class `pipeline/orchestrator.py::Pipeline.run`'s own
docstring documents fixing for the Docker deployment on 2026-10-19; this
sub-orchestration must not reintroduce it under its own fan-out shape).
"""
from __future__ import annotations

from culprit.serverless.orchestrators import (
    diagnose_cluster_orchestrator_generator as diagnose_cluster_orchestrator,
    pipeline_orchestrator_generator as pipeline_orchestrator,
)


class FakeTask:
    """A placeholder for whatever `context.call_activity`/
    `call_sub_orchestrator`/`task_all` would really return (a Durable
    Functions `Task`) - the orchestrator generator never inspects this
    object itself, only what the test `.send()`s back in, so it only
    needs to exist, not behave like a real Task."""


class FakeContext:
    def __init__(self, input_data):
        self._input = input_data
        self.calls: list[tuple] = []  # (kind, name, input) in call order

    def get_input(self):
        return self._input

    def call_activity(self, name, input_=None):
        self.calls.append(("activity", name, input_))
        return FakeTask()

    def call_sub_orchestrator(self, name, input_=None):
        self.calls.append(("sub_orchestrator", name, input_))
        return FakeTask()

    def task_all(self, tasks):
        self.calls.append(("task_all", "task_all", len(tasks)))
        return FakeTask()


def _drive(gen, *results):
    """Primes the generator to its first yield, then sends each result
    in turn - the standard way to manually step a Python generator-based
    orchestrator in a test, with no Durable Functions runtime involved."""
    next(gen)
    for result in results[:-1]:
        gen.send(result)
    try:
        gen.send(results[-1])
    except StopIteration as stop:
        return stop.value
    raise AssertionError("orchestrator did not complete after the given results - it yielded again")


# ── pipeline_orchestrator ───────────────────────────────────────────────

def test_pipeline_orchestrator_skips_cleanly_with_no_subscription_configured():
    ctx = FakeContext({"scope_name": "scheduled", "window_hours": 24, "trigger_mode": "scheduled"})
    gen = pipeline_orchestrator(ctx)

    result = _drive(gen, {"skip": "no_subscription_configured"})

    assert result == {"skipped": "no_subscription_configured"}
    assert [c[1] for c in ctx.calls] == ["discover_run_activity"]


def test_pipeline_orchestrator_handles_zero_machines_without_fanning_out_collection_or_diagnosis():
    ctx = FakeContext({"scope_name": "scheduled", "window_hours": 24, "trigger_mode": "scheduled"})
    gen = pipeline_orchestrator(ctx)

    result = _drive(
        gen,
        {"run": {"run_id": "run-1", "trigger_mode": "scheduled"}, "machines": [], "window_start": "2026-11-01T00:00:00+00:00", "window_end": "2026-11-01T08:00:00+00:00", "total_machines": 0},
        {"clusters": [], "history": []},
        {"run_id": "run-1", "total_failed": 0, "total_clusters": 0},
        {"notified": True},
    )

    assert result == {"run_id": "run-1", "total_failed": 0, "total_clusters": 0}
    names = [c[1] for c in ctx.calls]
    assert names == ["discover_run_activity", "cluster_and_checkpoint_activity", "finalize_run_activity", "notify_activity"]


def test_pipeline_orchestrator_fans_out_collection_and_diagnosis_and_partitions_member_bundles_correctly():
    ctx = FakeContext({"scope_name": "scheduled", "window_hours": 24, "trigger_mode": "scheduled"})
    gen = pipeline_orchestrator(ctx)

    machines = [{"vm_id": "vm-1"}, {"vm_id": "vm-2"}]
    bundles = [{"machine": {"vm_id": "vm-1"}, "v": "b1"}, {"machine": {"vm_id": "vm-2"}, "v": "b2"}]
    clusters = [{"cluster_id": "c1", "representative_vm_id": "vm-1", "members": [{"vm_id": "vm-1"}, {"vm_id": "vm-2"}]}]

    result = _drive(
        gen,
        {"run": {"run_id": "run-1", "trigger_mode": "scheduled"}, "machines": machines, "window_start": "ws", "window_end": "we", "total_machines": 2},
        bundles,
        {"clusters": clusters, "history": [["c0"]]},
        [{"cluster_id": "c1"}],
        {"run_id": "run-1", "total_failed": 2, "total_clusters": 1},
        {"notified": True},
    )

    assert result == {"run_id": "run-1", "total_failed": 2, "total_clusters": 1}
    names = [c[1] for c in ctx.calls]
    assert names == [
        "discover_run_activity", "collect_machine_activity", "collect_machine_activity",
        "task_all", "cluster_and_checkpoint_activity", "diagnose_cluster_orchestrator", "task_all",
        "finalize_run_activity", "notify_activity",
    ]

    # The part most likely to break silently: each cluster's sub-
    # orchestration must receive exactly its own members' bundles, by
    # looking them up by vm_id - not the whole fleet's bundles, and not
    # the wrong machine's bundle.
    sub_orch_call = next(c for c in ctx.calls if c[1] == "diagnose_cluster_orchestrator")
    sub_input = sub_orch_call[2]
    assert sub_input["member_bundles"] == bundles
    assert sub_input["history"] == [["c0"]]
    assert sub_input["window_start"] == "ws" and sub_input["window_end"] == "we"


# ── diagnose_cluster_orchestrator ───────────────────────────────────────

def _diagnose_input():
    return {
        "run_id": "run-1",
        "cluster": {"cluster_id": "c1", "representative_vm_id": "vm-1"},
        "member_bundles": [
            {"machine": {"vm_id": "vm-1"}, "v": "original"},
            {"machine": {"vm_id": "vm-2"}, "v": "m2"},
        ],
        "history": [],
        "window_start": "ws",
        "window_end": "we",
    }


def test_diagnose_cluster_orchestrator_settles_on_the_rule_engine_without_calling_the_llm():
    ctx = FakeContext(_diagnose_input())
    gen = diagnose_cluster_orchestrator(ctx)

    result = _drive(
        gen,
        {"cluster_id": "c1", "title": "settled by rules", "missing_evidence": []},
        {"cluster_id": "c1", "result": {"title": "settled by rules"}, "recurrence_badge": None, "consecutive_cycles": 1},
    )

    assert result == {"cluster_id": "c1", "result": {"title": "settled by rules"}, "recurrence_badge": None, "consecutive_cycles": 1}
    names = [c[1] for c in ctx.calls]
    assert names == ["evaluate_rules_activity", "advise_and_persist_activity"]


def test_diagnose_cluster_orchestrator_calls_deep_rca_when_rules_do_not_settle_it():
    ctx = FakeContext(_diagnose_input())
    gen = diagnose_cluster_orchestrator(ctx)

    result = _drive(
        gen,
        None,
        {"cluster_id": "c1", "title": "diagnosed", "missing_evidence": []},
        {"cluster_id": "c1", "result": {"title": "diagnosed"}, "recurrence_badge": None, "consecutive_cycles": 1},
    )

    assert result["result"]["title"] == "diagnosed"
    names = [c[1] for c in ctx.calls]
    assert names == ["evaluate_rules_activity", "deep_rca_activity", "advise_and_persist_activity"]


def test_diagnose_cluster_orchestrator_does_not_re_diagnose_when_recollection_finds_nothing_new():
    ctx = FakeContext(_diagnose_input())
    gen = diagnose_cluster_orchestrator(ctx)

    result = _drive(
        gen,
        None,
        {"cluster_id": "c1", "title": "first pass", "missing_evidence": ["disk_metrics"]},
        {"changed": False},
        {"cluster_id": "c1", "result": {"title": "first pass"}, "recurrence_badge": None, "consecutive_cycles": 1},
    )

    assert result["result"]["title"] == "first pass"
    names = [c[1] for c in ctx.calls]
    assert names == ["evaluate_rules_activity", "deep_rca_activity", "recollect_activity", "advise_and_persist_activity"]

    # Exactly one deep_rca_activity call - no silent second LLM call when
    # there was nothing new to re-diagnose with.
    assert names.count("deep_rca_activity") == 1

    # The persisted member_bundles must be the ORIGINAL, unchanged list -
    # recollection found nothing, so nothing should be swapped in.
    persist_call = next(c for c in ctx.calls if c[1] == "advise_and_persist_activity")
    assert persist_call[2]["member_bundles"] == _diagnose_input()["member_bundles"]


def test_diagnose_cluster_orchestrator_re_diagnoses_with_the_recollected_bundle_and_persists_it():
    """The regression this test exists to catch: a recollected
    representative's data must actually reach both the second deep-RCA
    call AND persistence - not just the second RCA call while
    `advise_and_persist_activity` silently persists the stale
    pre-recollection bundle (exactly the 2026-10-19 bug class
    `pipeline/orchestrator.py`'s own docstring documents fixing for the
    Docker deployment)."""
    ctx = FakeContext(_diagnose_input())
    gen = diagnose_cluster_orchestrator(ctx)

    recollected_bundle = {"machine": {"vm_id": "vm-1"}, "v": "recollected"}

    result = _drive(
        gen,
        None,
        {"cluster_id": "c1", "title": "first pass", "missing_evidence": ["disk_metrics"]},
        {"changed": True, "bundle": recollected_bundle},
        {"cluster_id": "c1", "title": "re-diagnosed", "missing_evidence": []},
        {"cluster_id": "c1", "result": {"title": "re-diagnosed"}, "recurrence_badge": None, "consecutive_cycles": 1},
    )

    assert result["result"]["title"] == "re-diagnosed"
    names = [c[1] for c in ctx.calls]
    assert names == [
        "evaluate_rules_activity", "deep_rca_activity", "recollect_activity",
        "deep_rca_activity", "advise_and_persist_activity",
    ]
    assert names.count("deep_rca_activity") == 2

    # The second deep_rca_activity call must carry the recollected bundle.
    second_deep_rca_call = [c for c in ctx.calls if c[1] == "deep_rca_activity"][1]
    assert second_deep_rca_call[2]["representative_bundle"] == recollected_bundle

    # And the persisted member_bundles must have vm-1's entry replaced
    # with the recollected bundle, while vm-2's is untouched.
    persist_call = next(c for c in ctx.calls if c[1] == "advise_and_persist_activity")
    persisted_bundles = {b["machine"]["vm_id"]: b for b in persist_call[2]["member_bundles"]}
    assert persisted_bundles["vm-1"] == recollected_bundle
    assert persisted_bundles["vm-2"] == {"machine": {"vm_id": "vm-2"}, "v": "m2"}
