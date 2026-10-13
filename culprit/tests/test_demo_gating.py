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

    resp = client.post("/runs/demo")
    assert resp.status_code == 200

    html = client.get("/").text
    assert "Demo scenario" in html


def test_demo_disabled_404s_the_route_and_hides_the_card(client, monkeypatch):
    monkeypatch.setattr(config, "settings", config.Settings(demo_enabled=False))

    resp = client.post("/runs/demo")
    assert resp.status_code == 404

    html = client.get("/").text
    assert "Demo scenario" not in html
    # The "Live analysis" card (real Azure/Datadog config) must still be
    # there - disabling the demo isn't disabling the whole console page.
    assert "Live analysis" in html
