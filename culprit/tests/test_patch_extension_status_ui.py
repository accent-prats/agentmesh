"""The machine drill-down page's new "Patch extension report" card
(machine.html.j2 + reporting/extension_status_view.py) - end to end via
the demo route, which generate_scenario.py now seeds with a realistic
Linux Patch Extension status finding for exactly this purpose."""
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


def test_machine_page_shows_the_patch_extension_report_card(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/machines/vm-prd-app-0100.html").text
    assert "Patch extension report" in html
    assert "Microsoft.CPlat.Core.LinuxPatchExtension" in html
    assert "PatchInstallationSummary" in html
    assert "no space left on device at /boot" in html
    assert "eg-detail-toggle" in html  # the top-level finding carries the raw status JSON


def test_a_machine_with_no_patch_extension_status_does_not_show_the_card(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]
    # vm-prd-legacy-0601 is the demo's "insufficient evidence" machine -
    # its guest collection never succeeded at all, so it has no extension
    # status findings (collection_gaps covers that case, a separate card).
    html = client.get(f"/runs/{run_id}/machines/vm-prd-legacy-0601.html").text
    assert "Patch extension report" not in html


def test_fleet_report_rolls_up_a_per_cluster_extension_finding_count(client):
    """Review flagged this as a currently-missing addition matching the
    sibling evidence-gap feature's own precedent of shipping at both the
    Fleet Report and machine-page altitudes, not just the latter."""
    from culprit.demo.generate_scenario import CLUSTER_SIZES

    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/report.html").text
    assert f"{CLUSTER_SIZES[0]} machines in this cluster also show" in html
    assert "patch-extension-reported error" in html


def test_fleet_report_omits_the_rollup_for_a_cluster_with_no_extension_findings(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]
    report = resp.json()
    # The "insufficient evidence" cluster (vm-prd-legacy-0601) never has
    # any patch_extension_status findings - its own card must not claim
    # a count of 0 machines, it must simply omit the rollup line.
    unresolved_cluster_id = next(
        e["cluster"]["cluster_id"] for e in report["entries"] if e["result"]["cause_family"] == "unresolved"
    )
    html = client.get(f"/runs/{run_id}/report.html").text
    cluster_html = html.split(f'id="cluster-{unresolved_cluster_id}"')[1].split('id="cluster-')[0]
    assert "patch-extension-reported error" not in cluster_html
