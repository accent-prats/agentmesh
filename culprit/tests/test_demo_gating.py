"""CULPRIT_DEMO_ENABLED (config.py) - gates both the Console page's "Demo
scenario" card and the POST /runs/demo route itself behind one flag, on
by default (preserves the existing dev/test/demo experience with zero
config), so a stakeholder-facing deployment can turn it off without any
code difference from this same codebase - see config.py's and
routes_runs.py's own comments on why. Added 2026-10-14."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from culprit import config
from culprit.db.engine import make_engine, make_session_factory


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

    from culprit.api.main import app

    return TestClient(app)


def test_demo_is_on_by_default(client):
    """The default must preserve today's behavior exactly - every other
    test in this whole suite relies on POST /runs/demo working with zero
    extra configuration."""
    assert config.settings.demo_enabled is True

    # Before any run exists, the Console page is the onboarding/empty
    # state - the full "Demo scenario" card is what shows there.
    html = client.get("/").text
    assert "Demo scenario" in html

    resp = client.post("/runs/demo")
    assert resp.status_code == 200

    # After a run completes, the Console page becomes the dashboard
    # state - the demo trigger is now a condensed action button instead
    # of repeating the full card (see console.html.j2), so check for the
    # button itself rather than the now-dashboard-only heading text.
    html = client.get("/").text
    assert 'id="run-btn"' in html


def test_demo_disabled_404s_the_route_and_hides_the_card(client, monkeypatch):
    monkeypatch.setattr(config, "settings", config.Settings(demo_enabled=False))

    resp = client.post("/runs/demo")
    assert resp.status_code == 404

    html = client.get("/").text
    assert "Demo scenario" not in html
    # The "Live analysis" card (real Azure/Datadog config) must still be
    # there - disabling the demo isn't disabling the whole console page.
    assert "Live analysis" in html


def test_demo_disabled_runs_page_empty_state_does_not_mention_the_demo(client, monkeypatch):
    """Found reviewing the gating work: the Runs page's empty state told a
    user with no runs yet to "trigger the demo scenario" from the Console -
    stale advice once that button no longer exists there."""
    monkeypatch.setattr(config, "settings", config.Settings(demo_enabled=False))

    html = client.get("/runs.html").text
    assert "No runs yet" in html
    assert "demo scenario" not in html.lower()
    assert "live analysis" in html.lower()
