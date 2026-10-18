"""The machine drill-down page's "Logs reviewed this run" reconciliation,
folded into the existing "Show full timeline" panel (added 2026-10-19,
replacing the previous day's standalone "Checks performed, no issues
found" card - user-requested: "add all logs being used and also the logs
not used in analysis, with a brief reason, in the Show full timeline
section for each VM"). End to end via the demo route, which
generate_scenario.py already populates with real checks_performed/
sources_attempted for exactly this purpose. Same client fixture shape as
test_evidence_timeline_ui.py."""
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


def test_machine_page_shows_logs_used_and_not_used_inside_the_timeline_panel(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/machines/vm-prd-app-0100.html").text
    # Lives inside the existing "Show full timeline" panel, not a separate card.
    assert "Show full timeline" in html
    assert "Logs reviewed this run" in html
    # A guest log checked this run and found healthy (demo scenario's own
    # checks_performed) - rendered with a "no issues" status, not silently
    # dropped.
    assert "subscription-manager (entitlement) status" in html
    assert "dpkg lock holder" in html
    assert "Checked" in html and "no issues found" in html
    # Azure Resource Graph genuinely produced the patch-result event in
    # this demo bundle - must show as used, not "not collected."
    assert "Azure Resource Graph" in html
    assert "Used in analysis" in html
    # The guest-level anomalies (apt/history.log, disk usage) must also
    # show as used, via checks_finding_counts (the TRUE, uncapped count) -
    # not silently miscategorized as "not collected" just because this
    # reconciliation no longer re-derives "used" from the timeline for
    # guest rows (see log_usage_view.py's own docstring on why).
    assert "apt install/upgrade history" in html
    assert "disk usage" in html
    # Datadog's own 2 events in this demo bundle must also show as used -
    # via checks_finding_counts, not timeline matching (azure_monitor.py's
    # Syslog query and datadog_collector.py's logs query are both
    # genuinely uncapped at the source, found exposed to the same
    # eviction risk as the guest rows by a second review the same day).
    assert "Datadog" in html
    # The demo bundle's sources_attempted never includes Azure Monitor -
    # must read as "not configured," not silently absent or miscategorized
    # as a generic gap.
    assert "Azure Monitor" in html
    assert "Not configured" in html
    # Still shows the full per-event list underneath, unchanged.
    assert "Full event-by-event timeline" in html
    assert "guest:df:" in html


def test_the_old_standalone_checks_performed_card_is_gone(client):
    """Folded into the timeline panel per the user's explicit placement
    request - must not also still render as its own separate card."""
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/machines/vm-prd-app-0100.html").text
    assert "Checks performed, no issues found" not in html


def test_a_machine_with_no_sources_attempted_data_shows_no_log_usage_section():
    """A run whose MachineOutcomeRecord predates sources_attempted_json
    (sources_attempted reads back as []) must not show fabricated "not
    configured"/"not collected" rows for data that was simply never
    captured - see log_usage_view.py's own build_log_usage_view docstring.
    Direct call (not via the demo route) since every demo machine carries
    real sources_attempted - this is the one way to exercise the
    genuinely-missing case."""
    from culprit.models.evidence import PatchOutcome
    from culprit.reporting.render import render_machine_html

    class _FakeMember:
        vm_id, vm_name, deviation_notes = "vm-1-id", "vm-1", []

    class _FakeCluster:
        run_id, representative_vm_id = "run-1", "vm-1-id"

    html = render_machine_html(
        cluster=_FakeCluster(), member=_FakeMember(), result=None,
        outcome=PatchOutcome(status="Failed"), checks_performed=["disk usage"], sources_attempted=[],
    )
    assert "Logs reviewed this run" not in html
