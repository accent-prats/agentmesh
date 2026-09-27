"""End-to-end test of the whole deterministic pipeline against the exact
scenario from the proposal: 312 machines, 47 failed, collapsing into 6
clusters (19/11/8/5/3/1) with the causes named in Sections 6 and 8.

Uses the scripted demo RCA agent (no network, no API key needed) for the
two clusters the rule engine can't settle - this test is about proving the
pipeline's wiring (clustering -> rules -> RCA -> advisor -> persistence ->
report), not about grading a live model's reasoning.
"""
from __future__ import annotations

from culprit.demo.generate_scenario import CLUSTER_SIZES, TOTAL_MACHINES, build_scenario
from culprit.demo.scripted_rca import ScriptedRCAAgent
from culprit.models.taxonomy import CauseFamily
from culprit.pipeline.orchestrator import Pipeline
from culprit.reporting.fleet_report import build_fleet_report
from culprit.retrieval.corpus import default_retrieval_store


def test_scenario_collapses_into_six_clusters_of_the_right_sizes(session_factory):
    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=ScriptedRCAAgent(), retrieval_store=default_retrieval_store())
    output = pipeline.run(run, bundles)

    assert len(output.diagnosed) == 6
    sizes = sorted((d.cluster.size for d in output.diagnosed), reverse=True)
    assert sizes == CLUSTER_SIZES


def test_four_of_six_clusters_are_settled_by_the_rule_engine_not_the_model(session_factory):
    from culprit.models.rca import ResultOrigin

    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=ScriptedRCAAgent(), retrieval_store=default_retrieval_store())
    output = pipeline.run(run, bundles)

    by_size = {d.cluster.size: d for d in output.diagnosed}
    assert by_size[19].result.origin == ResultOrigin.RULE_ENGINE
    assert by_size[19].result.cause_family == CauseFamily.CAPACITY
    assert by_size[11].result.origin == ResultOrigin.RULE_ENGINE
    assert by_size[11].result.cause_family == CauseFamily.CONFIGURATION
    assert by_size[5].result.origin == ResultOrigin.RULE_ENGINE
    assert by_size[5].result.cause_family == CauseFamily.AGENT_EXTENSION
    assert by_size[3].result.origin == ResultOrigin.RULE_ENGINE
    assert by_size[3].result.cause_family == CauseFamily.SOURCE_ENTITLEMENT

    # Only the window-exhaustion (8) and unresolved (1) clusters should
    # have gone to the (scripted, here) deep RCA agent.
    assert by_size[8].result.origin == ResultOrigin.DEEP_RCA
    assert by_size[8].result.cause_family == CauseFamily.WINDOW_SCHEDULING
    assert by_size[1].result.origin == ResultOrigin.DEEP_RCA
    assert by_size[1].result.cause_family == CauseFamily.UNRESOLVED


def test_every_causal_step_across_all_clusters_cites_evidence(session_factory):
    """The hard constraint, checked end to end: nothing that reaches the
    report has an uncited claim."""
    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=ScriptedRCAAgent(), retrieval_store=default_retrieval_store())
    output = pipeline.run(run, bundles)

    for diagnosed in output.diagnosed:
        for step in diagnosed.result.causal_chain:
            assert step.evidence_refs, f"uncited step in {diagnosed.cluster.cluster_id}: {step.statement}"


def test_fleet_report_totals_and_repeat_offender_detection(session_factory):
    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=ScriptedRCAAgent(), retrieval_store=default_retrieval_store())
    output = pipeline.run(run, bundles)
    report = build_fleet_report(output, total_machines=TOTAL_MACHINES)

    assert report.total_machines == TOTAL_MACHINES
    assert report.total_failed == 47
    assert report.total_clusters == 6
    assert report.compliance_pct == round(100.0 * (312 - 47) / 312, 1)
    # First run ever for this cluster_key - nothing should be flagged as a repeat yet.
    assert report.repeat_offender_count == 0
    assert report.entries[0].cluster.size == 19  # sorted largest-first


def test_second_run_with_the_same_causes_is_flagged_as_repeat_offender(session_factory):
    """Runs the same scenario twice (as two separate PatchRuns) to prove
    the cross-run recurrence detection actually reads run history, not
    just within-run state."""
    from datetime import timedelta

    run1, bundles1 = build_scenario()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=ScriptedRCAAgent(), retrieval_store=default_retrieval_store())
    pipeline.run(run1, bundles1)

    run2, bundles2 = build_scenario()
    run2 = run2.model_copy(update={"run_id": "mc-run-2026-10-03-prod-linux-weekly-0400", "started_at": run1.started_at + timedelta(days=7)})
    for b in bundles2:
        b.run_id = run2.run_id
    output2 = pipeline.run(run2, bundles2)

    by_size = {d.cluster.size: d for d in output2.diagnosed}
    assert by_size[19].recurrence.consecutive_cycles == 2
    assert by_size[19].recurrence.is_repeat_offender is True
    assert by_size[19].recurrence.badge == "2nd cycle recurring"
