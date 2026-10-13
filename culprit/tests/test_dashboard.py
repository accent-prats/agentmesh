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
    # A single run has nothing to trend against yet - FleetTrend's own
    # "no prior cycle" case, not an error.
    assert summary.compliance_trend == [] or len(summary.compliance_trend) == 1


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


def test_console_page_empty_state_unaffected(client):
    """Zero runs yet - the original onboarding content, unchanged."""
    html = client.get("/").text
    assert "Demo scenario" in html
    assert "Cause breakdown" not in html
