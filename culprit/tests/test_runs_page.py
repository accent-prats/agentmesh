"""Coverage for the Runs page's 2026-10-13 redesign - a client-side
search/filter/sort toolbar and summary tiles added on top of the
existing table, with no new route or backend logic. The one real risk
this review caught: TriggerMode/RunStage are `class X(str, Enum)`, and
bare Jinja interpolation of a raw enum member (`{{ value }}`) would have
rendered "TriggerMode.SCHEDULED" instead of "scheduled" - the data these
tests exercise is a RunSummary (always a plain `str` field after Pydantic
validation, confirmed empirically), not a raw ORM enum, so this is
mostly a belt-and-suspenders regression guard rather than a reproduction
of a currently-live bug."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from culprit.db import repository
from culprit.db.engine import make_engine, make_session_factory
from culprit.db.models import RunStage
from culprit.models.patch_run import PatchRun, TriggerMode
from culprit.reporting.render import render_runs_html


def _make_run(session, run_id, scope_name, trigger_mode, stage, started_at, total_machines=10, failed_machines=0):
    run = PatchRun(
        run_id=run_id, maintenance_configuration_id="mc-1", subscription_id="sub-1",
        scope_name=scope_name, started_at=started_at, total_machines=total_machines,
        trigger_mode=trigger_mode,
    )
    repository.save_run(session, run, stage=RunStage.STARTED)
    repository.update_run_stage(session, run_id, stage, ended_at=started_at, failed_machines=failed_machines)


def test_render_runs_html_derives_distinct_filter_options_from_the_data(session_factory):
    with session_factory() as session:
        _make_run(session, "run-1", "scope-a", TriggerMode.SCHEDULED, RunStage.COMPLETE, datetime(2026, 1, 1, tzinfo=timezone.utc))
        _make_run(session, "run-2", "scope-b", TriggerMode.AD_HOC, RunStage.COMPLETE, datetime(2026, 1, 2, tzinfo=timezone.utc))
        _make_run(session, "run-3", "scope-c", TriggerMode.SCHEDULED, RunStage.FAILED, datetime(2026, 1, 3, tzinfo=timezone.utc))
        runs = repository.list_runs(session)

    html = render_runs_html(runs)

    # Exactly one <option> per distinct value, not one per run (3 runs,
    # 2 distinct triggers, 2 distinct stages) - and critically, the clean
    # lowercase value, never the raw enum's "TriggerMode.SCHEDULED"-shaped
    # str() representation.
    assert html.count('<option value="scheduled">') == 1
    assert html.count('<option value="ad_hoc">') == 1
    assert "TriggerMode." not in html
    assert "RunStage." not in html
    assert html.count('<option value="complete">') == 1
    assert html.count('<option value="failed">') == 1

    # Each row's data attributes carry the same clean values the filter
    # dropdowns compare against - the two sides must agree or every
    # filter silently matches nothing.
    assert 'data-trigger="scheduled"' in html
    assert 'data-trigger="ad_hoc"' in html
    assert 'data-status="complete"' in html
    assert 'data-status="failed"' in html


def test_render_runs_html_includes_the_toolbar_and_summary_tiles_only_when_runs_exist(session_factory):
    with session_factory() as session:
        runs = repository.list_runs(session)

    empty_html = render_runs_html(runs)
    # The <script> block (unconditional, same file either way) mentions
    # these ids as JS string literals regardless - check for the actual
    # HTML element (`id="..."` attribute syntax), not a bare substring,
    # or this would false-negative on the script's own source text.
    assert 'id="runs-search"' not in empty_html
    assert 'id="stat-total"' not in empty_html
    assert "No runs yet" in empty_html

    with session_factory() as session:
        _make_run(session, "run-1", "scope-a", TriggerMode.SCHEDULED, RunStage.COMPLETE, datetime(2026, 1, 1, tzinfo=timezone.utc))
        runs = repository.list_runs(session)

    populated_html = render_runs_html(runs)
    assert 'id="runs-search"' in populated_html
    assert 'id="stat-total"' in populated_html
    assert 'id="stat-complete"' in populated_html
    assert 'id="stat-failed-runs"' in populated_html
    assert 'id="stat-failed-machines"' in populated_html
    assert "sortRuns(" in populated_html


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

    from culprit.api.main import app

    return TestClient(app)


def test_runs_page_http_renders_clean_filter_values_end_to_end(client):
    """Same guard as the render_runs_html tests above, but through the
    real route and a real DB round-trip (RunRecord -> RunSummary via
    repository.list_runs -> Jinja) rather than constructing a RunSummary
    by hand - the actual path a browser hits."""
    import culprit.api.deps as deps_module

    with deps_module.get_session_factory()() as session:
        _make_run(session, "run-1", "prod-weekly", TriggerMode.EVENT_DRIVEN, RunStage.COMPLETE, datetime(2026, 1, 1, tzinfo=timezone.utc))

    html = client.get("/runs.html").text
    assert 'data-trigger="event_driven"' in html
    assert 'data-status="complete"' in html
    assert "EventMode." not in html
    assert "TriggerMode." not in html
    assert "RunStage." not in html
