"""The machine drill-down page's new "Azure-reported install errors" card
(machine.html.j2 + reporting/azure_error_view.py) - end to end via the
demo route, which generate_scenario.py's _window_exceeded_bundle now
seeds with a realistic error_details entry (the real wording from the
live-tenant screenshot that prompted this feature) for exactly this
purpose."""
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


def test_machine_page_shows_the_azure_error_details_card(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/machines/vm-prd-batch-0300.html").text
    assert "Azure-reported install errors" in html
    assert "There is no enough time left to continue applying the next update" in html


def test_machine_page_omits_the_card_when_there_are_no_azure_error_details(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/machines/vm-prd-app-0100.html").text
    assert "Azure-reported install errors" not in html


def test_installation_report_shows_azure_error_details_in_raw_error_detail(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/installation-report.html").text
    assert "There is no enough time left to continue applying the next update" in html


def test_fleet_report_rolls_up_a_per_cluster_azure_error_count(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]
    report = resp.json()

    window_exceeded_cluster_id = next(
        e["cluster"]["cluster_id"] for e in report["entries"]
        if any(m["vm_name"] == "vm-prd-batch-0300" for m in e["cluster"]["members"])
    )
    html = client.get(f"/runs/{run_id}/report.html").text
    assert f'id="cluster-{window_exceeded_cluster_id}"' in html
    assert "Azure-reported install error - see each machine's own page for detail" in html
