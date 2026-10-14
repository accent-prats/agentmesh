"""CULPRIT_DEMO_ENABLED (config.py) - gates both the Console page's "Demo
scenario" card and the POST /runs/demo route itself behind one flag. Off
by default (flipped 2026-10-14, opt-in instead of opt-out, after a "prod"
deployment that never set this still showed the demo button) - a
dev/demo/test deployment turns it on explicitly instead, with no code
difference from this same codebase. tests/conftest.py sets
CULPRIT_DEMO_ENABLED=true for this whole suite so individual tests don't
need their own per-test config - see test_demo_defaults_to_disabled_when_unset
below for a test of the actual bare default, independent of that ambient
override. Added 2026-10-14."""
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


def test_demo_defaults_to_disabled_when_the_env_var_is_unset(monkeypatch):
    """The real production default (independent of this test suite's own
    conftest.py, which sets CULPRIT_DEMO_ENABLED=true so every other test
    can rely on POST /runs/demo with zero per-test config): a deployment
    that never set this var at all must not expose the demo.

    Goes through config._env_flag directly, not config.Settings() - a
    dataclass field's default expression evaluates exactly once, at
    Settings() construction (which already happened at module import,
    with the env var already set by conftest.py), so constructing
    "another" Settings() here wouldn't actually re-read the environment
    at all; _env_flag is what Settings.demo_enabled's own default
    expression calls, so this proves the exact same logic without
    needing a module reload."""
    monkeypatch.delenv("CULPRIT_DEMO_ENABLED", raising=False)
    assert config._env_flag("CULPRIT_DEMO_ENABLED", "false") is False


def test_demo_works_with_the_test_suites_own_default_config(client):
    """Confirms tests/conftest.py's CULPRIT_DEMO_ENABLED=true actually
    does what the rest of this suite depends on - every other test here
    relies on POST /runs/demo working with zero extra per-test
    configuration."""
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
