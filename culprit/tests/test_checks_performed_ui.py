"""The machine drill-down page's new "Checks performed, no issues found"
card (machine.html.j2) - end to end via the demo route, which
generate_scenario.py populates with real checks_performed for exactly
this purpose. Same client fixture shape as test_evidence_timeline_ui.py."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module
    from culprit.db.engine import make_engine, make_session_factory
    from culprit.demo.scripted_rca import ScriptedRCAAgent
    from culprit.retrieval.corpus import default_retrieval_store

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)
    monkeypatch.setattr(deps_module, "get_rca_agent", lambda: ScriptedRCAAgent())
    deps_module.get_retrieval_store.cache_clear()
    monkeypatch.setattr(deps_module, "get_retrieval_store", lambda: default_retrieval_store())

    from culprit.api.main import app

    return TestClient(app)


def test_machine_page_shows_the_checks_performed_card(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/machines/vm-prd-app-0100.html").text
    assert "Checks performed, no issues found" in html
    assert "subscription-manager (entitlement) status" in html
    assert "dpkg lock holder" in html


def test_a_machine_with_no_checks_performed_does_not_show_the_card():
    """A run diagnosed before checks_performed existed, or whose collectors
    never populated it, must not show an empty card - same "card omitted
    entirely, not shown empty" discipline as every other optional card on
    this page."""
    from culprit.models.evidence import PatchOutcome
    from culprit.reporting.render import render_machine_html

    class _FakeMember:
        vm_id, vm_name, deviation_notes = "vm-1-id", "vm-1", []

    class _FakeCluster:
        run_id, representative_vm_id = "run-1", "vm-1-id"

    html = render_machine_html(
        cluster=_FakeCluster(), member=_FakeMember(), result=None,
        outcome=PatchOutcome(status="Failed"), checks_performed=[],
    )
    assert "Checks performed, no issues found" not in html
