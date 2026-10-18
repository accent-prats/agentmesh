"""The machine drill-down page's new "Evidence timeline" card
(machine.html.j2 + reporting/evidence_timeline_view.py) - end to end via
the demo route, which generate_scenario.py already populates with a real
EvidenceBundle.timeline for exactly this purpose. Same client fixture
shape as test_patch_extension_status_ui.py."""
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


def test_machine_page_shows_the_evidence_timeline_card(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/machines/vm-prd-app-0100.html").text
    assert "Evidence timeline" in html
    assert "events the diagnosis above was reasoned from" in html
    # a real event from generate_scenario.py's own demo bundle, not a stub
    assert "apt/history.log Error: gzip: stdout: No space left on device" in html
    assert "/boot at 99% used, 3.2M free" in html
    assert "guest:df:" in html
    assert "eg-detail-toggle" in html
    assert "Show full timeline" in html


def test_a_machine_with_no_timeline_does_not_show_the_card():
    """A run diagnosed before timeline_json existed (outcome_record has no
    timeline, or there's no outcome row at all) must not show an
    empty/broken card - same "card omitted entirely, not shown empty"
    discipline as every other optional card on this page. Direct call
    (not via the demo route) since every demo machine carries at least
    one real timeline event - this is the one way to exercise the
    genuinely-empty case."""
    from culprit.models.evidence import PatchOutcome
    from culprit.reporting.render import render_machine_html

    class _FakeMember:
        vm_id, vm_name, deviation_notes = "vm-1-id", "vm-1", []

    class _FakeCluster:
        run_id, representative_vm_id = "run-1", "vm-1-id"

    html = render_machine_html(
        cluster=_FakeCluster(), member=_FakeMember(), result=None,
        outcome=PatchOutcome(status="Failed"), timeline=[],
    )
    assert "Evidence timeline" not in html
