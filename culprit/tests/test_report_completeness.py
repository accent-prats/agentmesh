"""Coverage for the report-completeness gaps found in the 2026-09-27
proposal audit: evidence citations and ruled-out causes reaching the
rendered report, cycle-over-cycle trend, the verdict -> retrieval
feedback loop, and the per-machine drill-down (proposal Section 8's
third altitude).
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory
from culprit.demo.generate_scenario import build_scenario
from culprit.demo.scripted_rca import ScriptedRCAAgent
from culprit.pipeline.orchestrator import Pipeline
from culprit.retrieval.corpus import default_retrieval_store


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

    monkeypatch.setattr(deps_module, "get_rca_agent", lambda: ScriptedRCAAgent())

    deps_module.get_retrieval_store.cache_clear()
    store = default_retrieval_store()
    monkeypatch.setattr(deps_module, "get_retrieval_store", lambda: store)

    from culprit.api.main import app

    return TestClient(app), store


def test_fleet_report_html_honors_the_configured_display_timezone(client):
    """2026-09-26 04:00 UTC (the demo scenario's own WINDOW_START,
    generate_scenario.py:47) must render as 09:30 IST under Asia/Kolkata -
    proves the admin-configurable display timezone (models/settings.py::
    DisplayTimezoneSettingsInput) actually reaches the rendered HTML, not
    just the unit-level localtime filter."""
    test_client, _ = client
    put_resp = test_client.put("/settings/display-timezone", json={"timezone": "Asia/Kolkata"})
    assert put_resp.status_code == 200

    resp = test_client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]
    html = test_client.get(f"/runs/{run_id}/report.html").text
    assert "2026-09-26 09:30 IST" in html
    assert "2026-09-26 04:00 UTC" not in html


def test_fleet_report_html_shows_evidence_citations_and_ruled_out(client):
    """The proposal's "no citation, no claim" hard constraint is enforced
    at the model layer (models/rca.py) - this proves the citations it
    forces actually reach the page a reviewer reads, not just the JSON."""
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = test_client.get(f"/runs/{run_id}/report.html").text
    assert "evidence:" in html
    # The window-exhaustion cluster (8 machines) is diagnosed by the
    # scripted deep-RCA agent, which populates ruled_out - see
    # demo/scripted_rca.py.
    assert "Ruled out" in html


def test_fleet_report_json_includes_a_machine_row_per_failed_machine(client):
    """machine_rows (added 2026-10-13 for the fleet report's per-machine
    table) must cover every failed machine exactly once, batch-joined
    against MachineOutcomeRecord - not the per-machine N+1 query
    get_machine_detail uses, which would be fine for one machine but not
    for a whole fleet's worth."""
    test_client, _ = client
    report = test_client.post("/runs/demo").json()

    assert len(report["machine_rows"]) == report["total_failed"]
    vm_names = {row["vm_name"] for row in report["machine_rows"]}
    assert len(vm_names) == len(report["machine_rows"])  # no duplicates, no machine missing

    # This demo run post-dates MachineOutcomeRecord (see
    # test_machine_drill_down_shows_the_machines_own_patch_outcome), so
    # every row should have a real outcome, not the "predates per-machine
    # outcome tracking" None case.
    assert all(row["outcome"] is not None for row in report["machine_rows"])
    assert all(row["outcome"]["status"] for row in report["machine_rows"])


def test_fleet_report_html_shows_the_machine_table(client):
    """The table itself, plus its search/filter affordances and a working
    jump-to-cluster-card anchor - the actual UI surface, not just the data
    feeding it."""
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    report = resp.json()
    run_id = report["run"]["run_id"]
    first_row = report["machine_rows"][0]

    html = test_client.get(f"/runs/{run_id}/report.html").text
    assert 'id="fr-table"' in html
    assert 'id="fr-search"' in html
    assert first_row["vm_name"] in html
    # The table row's root-cause link and the card's own id must agree,
    # or clicking a row silently goes nowhere.
    anchor = f'#cluster-{first_row["cluster_id"]}'
    assert anchor in html
    assert f'id="cluster-{first_row["cluster_id"]}"' in html


def test_fleet_report_html_verdict_widget_present_and_wired_to_relative_verdicts_path(client):
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = test_client.get(f"/runs/{run_id}/report.html").text
    assert 'class="verdict-widget"' not in html or "data-cluster-id" in html
    assert "../../verdicts" in html
    assert "Was this finding right?" in html


def test_second_cycle_report_shows_trend_against_the_first(client):
    test_client, _ = client
    run1, bundles1 = build_scenario()

    # Drive the pipeline directly against the same in-memory DB the
    # client's app is wired to, so both runs land in one history.
    import culprit.api.deps as deps_module

    pipeline = Pipeline(
        session_factory=deps_module.get_session_factory(),
        rca_agent=ScriptedRCAAgent(),
        retrieval_store=default_retrieval_store(),
    )
    pipeline.run(run1, bundles1)

    run2, bundles2 = build_scenario()
    run2 = run2.model_copy(
        update={"run_id": "mc-run-2026-10-03-prod-linux-weekly-0400", "started_at": run1.started_at + timedelta(days=7)}
    )
    for b in bundles2:
        b.run_id = run2.run_id
    pipeline.run(run2, bundles2)

    html = test_client.get(f"/runs/{run2.run_id}/report.html").text
    assert "vs. previous cycle" in html
    assert run1.run_id in html

    resp = test_client.get(f"/runs/{run2.run_id}/report")
    trend = resp.json()["trend"]
    assert trend is not None
    assert trend["previous_run_id"] == run1.run_id
    assert trend["failed_delta"] == 0  # identical scenario run twice


def test_first_cycle_report_has_no_trend(client):
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    resp2 = test_client.get(f"/runs/{run_id}/report")
    assert resp2.json()["trend"] is None


@pytest.mark.parametrize(
    "failed_delta,compliance_delta_pct,expected_failed_arrow,expected_failed_color,expected_compliance_arrow,expected_compliance_color",
    [
        (-5, 2.3, "&darr;5", "text-emerald-600", "&uarr;2.3", "text-emerald-600"),
        (7, -1.8, "&uarr;7", "text-red-600", "&darr;1.8", "text-red-600"),
    ],
)
def test_fleet_report_html_trend_arrows_point_the_right_way(
    failed_delta, compliance_delta_pct, expected_failed_arrow, expected_failed_color,
    expected_compliance_arrow, expected_compliance_color,
):
    """Direct template render with a manufactured non-zero trend - the
    API-level trend test only ever produces a zero delta (the same
    scenario run twice), which never exercised the up/down arrow
    branches at all."""
    from culprit.models.report import FleetTrend
    from culprit.reporting.fleet_report import build_fleet_report
    from culprit.reporting.render import render_fleet_report_html
    from culprit.db.engine import make_engine, make_session_factory

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=factory, rca_agent=ScriptedRCAAgent(), retrieval_store=default_retrieval_store())
    output = pipeline.run(run, bundles)
    report = build_fleet_report(output, total_machines=312, bundles=bundles)

    trend = FleetTrend(
        previous_run_id="prev-run", previous_total_failed=99, previous_compliance_pct=80.0,
        previous_repeat_offender_count=1, failed_delta=failed_delta, compliance_delta_pct=compliance_delta_pct,
    )
    html = render_fleet_report_html(report.model_copy(update={"trend": trend}))

    assert f'<span class="{expected_failed_color} font-semibold">{expected_failed_arrow}</span>' in html
    assert f'<span class="{expected_compliance_color} font-semibold">{expected_compliance_arrow}</span>' in html


def test_build_fleet_report_computes_has_azure_error_detail_per_machine():
    """Review caught this: build_fleet_report (the standalone, in-memory
    construction path demo/run_demo.py's CLI script uses - a second,
    independent FleetReport builder from db/repository.py::
    _load_fleet_report_core's own DB-backed one, per this module's own
    docstring on an earlier, identical oversight 2026-10-13) was never
    updated to compute has_azure_error_detail when that field was added -
    so the CLI demo script's generated report silently never showed the
    new Azure-error rollup, even though the DB-backed /runs/demo route
    did. _window_exceeded_bundle (vm-prd-batch-030x) is the one bundle
    seeded with a real error_details entry; every other machine must read
    False."""
    from culprit.reporting.fleet_report import build_fleet_report

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=factory, rca_agent=ScriptedRCAAgent(), retrieval_store=default_retrieval_store())
    output = pipeline.run(run, bundles)
    report = build_fleet_report(output, total_machines=312, bundles=bundles)

    rows_by_name = {r.vm_name: r for r in report.machine_rows}
    assert rows_by_name["vm-prd-batch-0300"].has_azure_error_detail is True
    assert rows_by_name["vm-prd-app-0100"].has_azure_error_detail is False


def test_correct_verdict_adds_a_resolved_incident_to_the_retrieval_store(client):
    test_client, store = client
    resp = test_client.post("/runs/demo")
    body = resp.json()
    # The 19-machine disk-exhaustion cluster is rule-settled - pick it by size.
    entry = next(e for e in body["entries"] if len(e["cluster"]["members"]) == 19)
    cluster_id = entry["cluster"]["cluster_id"]

    before = len(store._documents)
    verdict_resp = test_client.post(
        "/verdicts",
        json={
            "cluster_id": cluster_id,
            "cause_family": "capacity",
            "verdict": "correct",
            "reviewer": "alice@example.com",
        },
    )
    assert verdict_resp.status_code == 200
    assert len(store._documents) == before + 1
    assert store._documents[-1].kind == "resolved_incident"


def test_wrong_verdict_does_not_add_a_resolved_incident(client):
    """Only a confirmed-correct verdict is a clean example to learn from -
    see the docstring in routes_verdicts.py."""
    test_client, store = client
    resp = test_client.post("/runs/demo")
    entry = resp.json()["entries"][0]
    cluster_id = entry["cluster"]["cluster_id"]

    before = len(store._documents)
    test_client.post(
        "/verdicts",
        json={
            "cluster_id": cluster_id,
            "cause_family": entry["result"]["cause_family"],
            "verdict": "wrong",
            "reviewer": "alice@example.com",
        },
    )
    assert len(store._documents) == before


def test_verdict_for_a_cluster_id_with_no_rca_result_does_not_crash(client):
    """test_api.py's existing test posts a verdict for a made-up
    cluster_id that was never diagnosed - the retrieval feedback step must
    stay a no-op for that case, not raise."""
    test_client, store = client
    resp = test_client.post(
        "/verdicts",
        json={
            "cluster_id": "some-cluster-that-does-not-exist",
            "cause_family": "capacity",
            "verdict": "correct",
            "reviewer": "alice@example.com",
        },
    )
    assert resp.status_code == 200


def test_precision_html_page_renders(client):
    test_client, _ = client
    test_client.post("/runs/demo")
    resp = test_client.get("/precision.html")
    assert resp.status_code == 200
    assert "automation gate" in resp.text


def test_machine_drill_down_page_renders_for_a_cluster_member(client):
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    entry = resp.json()["entries"][0]
    run_id = resp.json()["run"]["run_id"]
    vm_name = entry["cluster"]["members"][0]["vm_name"]

    machine_resp = test_client.get(f"/runs/{run_id}/machines/{vm_name}.html")
    assert machine_resp.status_code == 200
    assert vm_name in machine_resp.text


def test_fleet_report_machine_links_resolve_without_a_doubled_run_id(client):
    """Real bug found live: fleet_report.html.j2's machine-row and
    cluster-member links used `href="{run_id}/machines/{vm}.html"`, but
    report.html is itself already served at /runs/{run_id}/report.html -
    a browser resolves that relative href against the *current* page's
    own directory, so it doubled the run_id segment
    (/runs/{run_id}/{run_id}/machines/{vm}.html, a 404) instead of
    reaching the real machine page one directory down. The correct
    relative href (this test's own assertion) is just
    "machines/{vm}.html", with no run_id prefix - same convention the
    "View installation report" link right above it already used."""
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]
    vm_name = resp.json()["entries"][0]["cluster"]["members"][0]["vm_name"]

    html = test_client.get(f"/runs/{run_id}/report.html").text
    assert f'href="{run_id}/machines/' not in html
    assert f'href="machines/{vm_name}.html"' in html


def test_running_the_demo_twice_does_not_break_the_machine_page(client):
    """Real bug found in review: the demo scenario reuses a fixed RUN_ID
    on every call (culprit/demo/generate_scenario.py), so a second demo
    run re-diagnoses the same run_id - save_machine_outcomes used to
    blindly insert every call, leaving two MachineOutcomeRecord rows per
    machine and crashing get_machine_detail's lookup with
    MultipleResultsFound (a 500 on every machine page afterward).
    save_machine_outcomes now upserts on the same (run_id, vm_id)
    composite key save_cluster/save_rca_result already use for exactly
    this re-diagnosis case."""
    test_client, _ = client
    test_client.post("/runs/demo")
    resp = test_client.post("/runs/demo")  # same fixed run_id both times
    entry = resp.json()["entries"][0]
    run_id = resp.json()["run"]["run_id"]
    vm_name = entry["cluster"]["members"][0]["vm_name"]

    machine_resp = test_client.get(f"/runs/{run_id}/machines/{vm_name}.html")
    assert machine_resp.status_code == 200
    assert "What failed" in machine_resp.text


def test_machine_drill_down_shows_the_machines_own_patch_outcome(client):
    """A run diagnosed after MachineOutcomeRecord existed must show the
    machine's actual failure detail (status/error code), not the "this run
    predates per-machine outcome tracking" fallback - that fallback is only
    for runs saved before this table existed."""
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    entry = resp.json()["entries"][0]
    run_id = resp.json()["run"]["run_id"]
    vm_name = entry["cluster"]["members"][0]["vm_name"]

    html = test_client.get(f"/runs/{run_id}/machines/{vm_name}.html").text
    assert "What failed" in html
    assert "predates per-machine outcome tracking" not in html


def test_machine_drill_down_shows_the_real_rca_substance_for_a_rich_cluster(client):
    """Found 2026-10-16: render_machine_html already received the
    machine's full RCAResult (causal_chain, ruled_out, remediation -
    render.py never stripped any of it), but machine.html.j2 only ever
    rendered 3 of its ~10 fields (title, cause_family, confidence) - a
    user drilling into a specific machine saw none of the actual
    reasoning or recommended fix that's already shown on the Fleet
    Report's cluster card. vm-prd-app-0100 is the boot-full/capacity
    cluster's representative - has a real causal chain, no ruled-out
    candidates in this fixture, and a real remediation plan."""
    test_client, _ = client
    test_client.post("/runs/demo")
    run_id = "mc-run-2026-09-26-prod-linux-weekly-0400"

    html = test_client.get(f"/runs/{run_id}/machines/vm-prd-app-0100.html").text
    assert "Root cause" in html
    assert "Causal chain" in html
    assert "Free space on /boot was below threshold at run time" in html
    assert "Recommended fix" in html
    assert "Free space on /boot" in html  # the immediate fix's own first step
    assert "Automation candidate" in html
    assert "Open in Azure Portal" in html
    assert 'href="https://portal.azure.com/#@/resource/subscriptions/' in html
    # 19 machines in this cluster (CLUSTER_SIZES[0]) - this one plus 18 siblings.
    assert "Other machines with this cause" in html
    assert "vm-prd-app-0101" in html


def test_machine_drill_down_shows_missing_evidence_for_a_thin_cluster(client):
    """vm-prd-legacy-0601 is the demo's deliberately thin/unresolved
    machine (collection_gaps for guest_windows + azure_monitor, cluster
    size 1) - exactly the shape of machine the original bug report
    screenshotted as "vague." Confirms result.missing_evidence (the RCA
    agent's own "what I'd need" list) now renders, and that a
    single-machine cluster correctly omits the sibling-machines section
    rather than showing an empty one."""
    test_client, _ = client
    test_client.post("/runs/demo")
    run_id = "mc-run-2026-09-26-prod-linux-weekly-0400"

    html = test_client.get(f"/runs/{run_id}/machines/vm-prd-legacy-0601.html").text
    assert "Low confidence" in html
    assert "Missing evidence" in html
    assert "Other machines with this cause" not in html


def test_machine_drill_down_404s_for_an_unknown_vm(client):
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    machine_resp = test_client.get(f"/runs/{run_id}/machines/vm-does-not-exist.html")
    assert machine_resp.status_code == 404


def test_runs_page_lists_a_completed_run(client):
    test_client, _ = client
    resp = test_client.post("/runs/demo")
    run = resp.json()["run"]

    runs_resp = test_client.get("/runs.html")
    assert runs_resp.status_code == 200
    assert run["scope_name"] in runs_resp.text
    assert run["maintenance_configuration_id"] in runs_resp.text
    assert "Complete" in runs_resp.text


def test_runs_page_is_empty_before_any_run(client):
    test_client, _ = client
    html = test_client.get("/runs.html").text
    assert "No runs yet" in html
