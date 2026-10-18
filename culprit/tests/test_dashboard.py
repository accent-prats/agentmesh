"""Coverage for the Console dashboard's data layer (db/repository.py's
latest_completed_run_id/compliance_trend/top_causes/build_dashboard_summary,
models/dashboard.py) and its rendering, added 2026-10-15 to replace the
bare launcher page with a real at-a-glance view."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from culprit.db import repository
from culprit.db.engine import make_engine, make_session_factory
from culprit.db.models import RunStage
from culprit.models.dashboard import CauseBreakdownEntry
from culprit.models.patch_run import PatchRun
from culprit.models.taxonomy import CauseFamily


def _make_run(session, run_id: str, scope_name: str, started_at, total_machines: int, failed_machines: int):
    run = PatchRun(
        run_id=run_id,
        maintenance_configuration_id="mc-1",
        subscription_id="sub-1",
        scope_name=scope_name,
        started_at=started_at,
        total_machines=total_machines,
    )
    repository.save_run(session, run, stage=RunStage.STARTED)
    repository.update_run_stage(
        session, run_id, RunStage.COMPLETE, ended_at=started_at, failed_machines=failed_machines
    )


def test_latest_completed_run_id_is_none_with_no_runs(session_factory):
    with session_factory() as session:
        assert repository.latest_completed_run_id(session) is None


def test_latest_completed_run_id_returns_the_most_recent(session_factory):
    with session_factory() as session:
        _make_run(session, "run-older", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc), 100, 10)
        _make_run(session, "run-newer", "scope-a", datetime(2026, 1, 2, tzinfo=timezone.utc), 100, 5)
        assert repository.latest_completed_run_id(session) == "run-newer"


def test_latest_completed_run_id_ignores_incomplete_runs(session_factory):
    with session_factory() as session:
        _make_run(session, "run-complete", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc), 100, 10)
        run = PatchRun(
            run_id="run-in-progress", maintenance_configuration_id="mc-1", subscription_id="sub-1",
            scope_name="scope-a", started_at=datetime(2026, 1, 2, tzinfo=timezone.utc), total_machines=100,
        )
        repository.save_run(session, run, stage=RunStage.CLUSTERED)  # never reaches COMPLETE
        assert repository.latest_completed_run_id(session) == "run-complete"


def test_compliance_trend_orders_oldest_first_and_computes_percent(session_factory):
    with session_factory() as session:
        _make_run(session, "run-1", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc), 100, 20)  # 80%
        _make_run(session, "run-2", "scope-a", datetime(2026, 1, 2, tzinfo=timezone.utc), 100, 10)  # 90%
        _make_run(session, "run-3", "scope-a", datetime(2026, 1, 3, tzinfo=timezone.utc), 100, 5)  # 95%

        trend = repository.compliance_trend(session, "scope-a")

    assert [p.run_id for p in trend] == ["run-1", "run-2", "run-3"]  # oldest first
    assert [p.compliance_pct for p in trend] == [80.0, 90.0, 95.0]


def test_compliance_trend_is_scoped_to_one_scope_name(session_factory):
    with session_factory() as session:
        _make_run(session, "run-a", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc), 100, 10)
        _make_run(session, "run-b", "scope-b", datetime(2026, 1, 2, tzinfo=timezone.utc), 100, 50)

        trend = repository.compliance_trend(session, "scope-a")

    assert [p.run_id for p in trend] == ["run-a"]


def test_compliance_trend_respects_limit(session_factory):
    with session_factory() as session:
        for i in range(5):
            _make_run(session, f"run-{i}", "scope-a", datetime(2026, 1, 1 + i, tzinfo=timezone.utc), 100, 10)

        trend = repository.compliance_trend(session, "scope-a", limit=2)

    # The *most recent* 2, still returned oldest-first.
    assert [p.run_id for p in trend] == ["run-3", "run-4"]


def _run_demo_scenario(session_factory):
    from culprit.demo.generate_scenario import TOTAL_MACHINES, build_scenario
    from culprit.demo.scripted_rca import ScriptedRCAAgent
    from culprit.pipeline.orchestrator import Pipeline
    from culprit.retrieval.corpus import default_retrieval_store

    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=ScriptedRCAAgent(), retrieval_store=default_retrieval_store())
    return pipeline.run(run, bundles), TOTAL_MACHINES


def test_top_causes_ranks_by_machine_count(session_factory):
    output, _ = _run_demo_scenario(session_factory)

    with session_factory() as session:
        causes = repository.top_causes(session, output.run.run_id)

    # The demo scenario's largest cluster (19 machines) is a capacity
    # (disk exhaustion) failure - see demo/generate_scenario.py.
    assert causes[0].cause_family == CauseFamily.CAPACITY
    assert causes[0].machines == 19
    assert causes == sorted(causes, key=lambda c: -c.machines)  # strictly descending
    # All 6 of the demo scenario's distinct causes, not truncated at a
    # default limit - found 2026-10-15, a limit=5 default silently cut
    # off the smallest (1-machine "unresolved") cluster, looking wrong
    # next to the dashboard's own "6 distinct causes" stat tile.
    assert len(causes) == 6
    assert CauseFamily.UNRESOLVED in [c.cause_family for c in causes]


def _add_cause(session, run_id: str, cause_family: CauseFamily, machines: int, cluster_id: str):
    """Minimal Cluster + RCAResult row for one run, for tests that only
    care about top_causes' aggregation - not a full pipeline run like
    _run_demo_scenario (which is realistic but only ever produces one
    run_id per call, not the multi-run fixture these tests need)."""
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.rca import CausalStep, RCAResult, ResultOrigin
    from culprit.models.taxonomy import CauseFamily as CF
    from culprit.models.evidence import OSFamily

    members = [ClusterMember(vm_id=f"vm-{cluster_id}-{i}", vm_name=f"vm-{cluster_id}-{i}") for i in range(machines)]
    cluster = Cluster(
        cluster_id=cluster_id, run_id=run_id, cluster_key=cluster_id,
        fingerprint=Fingerprint(error_code_normalized="x", os_family=OSFamily.LINUX, failing_target=""),
        members=members, representative_vm_id=members[0].vm_id,
    )
    repository.save_cluster(session, cluster)
    repository.save_rca_result(session, RCAResult(
        cluster_id=cluster_id, origin=ResultOrigin.RULE_ENGINE, cause_family=cause_family,
        title="t", causal_chain=[CausalStep(order=1, statement="s", evidence_refs=["e1"])], confidence=0.9,
    ))


def test_top_causes_accepts_a_list_of_run_ids_and_sums_across_them():
    """Found 2026-10-18 from a real screenshot: Cause Breakdown used to be
    scoped to a single run_id, making it empty whenever the latest cycle
    alone had zero failures, right next to a Compliance Trend chart
    confidently showing 10 cycles of history. top_causes must be able to
    sum the same cause across multiple runs, not just report per-run."""
    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)
    with session_factory() as session:
        _make_run(session, "run-1", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc), 100, 10)
        _make_run(session, "run-2", "scope-a", datetime(2026, 1, 2, tzinfo=timezone.utc), 100, 15)
        _add_cause(session, "run-1", CauseFamily.CAPACITY, 10, "c1")
        _add_cause(session, "run-2", CauseFamily.CAPACITY, 5, "c2")
        _add_cause(session, "run-2", CauseFamily.CONFIGURATION, 10, "c3")

        single = repository.top_causes(session, "run-1")
        combined = repository.top_causes(session, ["run-1", "run-2"])

    assert single == [CauseBreakdownEntry(cause_family=CauseFamily.CAPACITY, machines=10)]
    # capacity summed across both runs (10 + 5 = 15), configuration only in run-2
    assert {(c.cause_family, c.machines) for c in combined} == {
        (CauseFamily.CAPACITY, 15), (CauseFamily.CONFIGURATION, 10),
    }


def test_build_dashboard_summary_shows_causes_from_a_healthy_latest_run_too(session_factory):
    """The actual bug this round fixes: a healthy latest cycle (zero
    failures, so no clusters/RCAResult of its own) must not empty out the
    whole card when earlier cycles in the same trend window had real
    diagnosed causes."""
    with session_factory() as session:
        _make_run(session, "run-1", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc), 100, 20)
        _add_cause(session, "run-1", CauseFamily.CAPACITY, 20, "c1")
        _make_run(session, "run-2", "scope-a", datetime(2026, 1, 2, tzinfo=timezone.utc), 100, 0)  # healthy, no clusters

        summary = repository.build_dashboard_summary(session)

    assert summary.latest_run.run.run_id == "run-2"
    assert summary.top_causes == [CauseBreakdownEntry(cause_family=CauseFamily.CAPACITY, machines=20)]


def test_build_dashboard_summary_is_empty_with_no_completed_runs(session_factory):
    with session_factory() as session:
        summary = repository.build_dashboard_summary(session)

    assert summary.latest_run is None
    assert summary.compliance_trend == []
    assert summary.top_causes == []


def test_build_dashboard_summary_populated_after_a_run(session_factory):
    output, total_machines = _run_demo_scenario(session_factory)

    with session_factory() as session:
        summary = repository.build_dashboard_summary(session)

    assert summary.latest_run is not None
    assert summary.latest_run.run.run_id == output.run.run_id
    assert summary.latest_run.total_failed == 47
    assert summary.top_causes  # populated, exact ranking covered above
    # compliance_trend always includes the run itself (it's a completed
    # run for this scope, same as any other) - a single point isn't a
    # *trend* (render.py gates the chart on >= 2), but it's a real,
    # correctly-populated list, not an empty one.
    assert len(summary.compliance_trend) == 1
    assert summary.compliance_trend[0].run_id == output.run.run_id
    # Only one completed run for this scope - no prior cycle to diff against.
    assert summary.failed_delta is None
    assert summary.compliance_delta_pct is None


def test_build_dashboard_summary_computes_deltas_from_two_runs(session_factory):
    with session_factory() as session:
        _make_run(session, "run-1", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc), 100, 20)  # 80%
        _make_run(session, "run-2", "scope-a", datetime(2026, 1, 2, tzinfo=timezone.utc), 100, 5)  # 95%

        summary = repository.build_dashboard_summary(session)

    assert summary.failed_delta == -15  # 5 - 20
    assert summary.compliance_delta_pct == 15.0  # 95.0 - 80.0


def test_build_dashboard_summary_does_not_need_previous_runs_clusters(session_factory):
    """The whole point of the optimization: build_dashboard_summary must no
    longer call compute_trend/_load_fleet_report_core on the *previous* run -
    a previous run with no Cluster/RCAResult rows at all (just the bare
    RunRecord _make_run creates) must still produce correct deltas instead
    of erroring or silently returning None, proving the dashboard reads
    failed_machines straight off RunRecord rather than reconstructing the
    previous run's clusters."""
    with session_factory() as session:
        _make_run(session, "run-1", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc), 100, 30)  # 70%, no clusters
        _make_run(session, "run-2", "scope-a", datetime(2026, 1, 2, tzinfo=timezone.utc), 100, 10)  # 90%, no clusters

        summary = repository.build_dashboard_summary(session)

    assert summary.failed_delta == -20
    assert summary.compliance_delta_pct == 20.0
    assert summary.latest_run.trend is None  # see DashboardSummary's docstring


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

    from culprit.api.main import app

    return TestClient(app)


def test_console_page_shows_dashboard_sections_after_a_run(client):
    resp = client.post("/runs/demo")
    assert resp.status_code == 200

    html = client.get("/").text
    assert "Cause breakdown" in html
    assert "Capacity" in html  # the top cause, human-labeled (cause_family.value "capacity" -> "Capacity")
    assert "View full report" in html
    # Only one completed run exists - no trend chart yet, same as a
    # single-point FleetTrend being absent rather than drawn broken.
    assert "Not enough completed cycles yet" in html
    # Found 2026-10-18: Cause breakdown's own header must track the same
    # window Compliance trend charts, not say "this cycle" - with exactly
    # one completed run so far, both cards agree on "last 1 cycle" -
    # singular, not the "last 1 cycles" grammar slip the Compliance trend
    # header already had before this round touched the same expression.
    assert html.count("last 1 cycle") == 2  # both cards, singular
    assert "1 cycles" not in html
    assert "this cycle" not in html
    assert "this cycle" not in html


def test_console_page_empty_state_unaffected(client):
    """Zero runs yet - the original onboarding content, unchanged."""
    html = client.get("/").text
    assert "Demo scenario" in html
    assert "Cause breakdown" not in html
