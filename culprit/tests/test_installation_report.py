"""Coverage for the Patch Installation Report (models/installation_report.py,
pipeline/installation_report.py, the new discovery.py query, and the
/runs/{run_id}/installation-report(.html) routes) - the Azure Update
Manager-style full-fleet view, built once per run (live or demo) right
after that run's own RCA pipeline completes.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory
from culprit.models.installation_report import InstallationStatus
from culprit.models.evidence import OSFamily
from culprit.pipeline.discovery import _identity_from_vm_id, _rows_to_outcomes
from culprit.pipeline.installation_report import _guest_log_path, _status_from_raw, build_installation_report


# ── Pure-function tests (no live Resource Graph call) ─────────────────────────

def test_rows_to_outcomes_parses_fields_and_drops_blanks():
    rows = [
        {"vmId": "/subscriptions/s/.../vm-1", "status": "Succeeded", "startDateTime": "2026-09-26T04:00:00Z", "lastModifiedDateTime": "2026-09-26T04:12:00Z"},
        {"vmId": ""},  # dropped - no vm id at all
        {"vmId": "/subscriptions/s/.../vm-2", "status": None, "startDateTime": None, "lastModifiedDateTime": None},
        {"vmId": "/subscriptions/s/.../vm-3", "status": "Failed", "startDateTime": "2026-09-26T04:00:00Z", "lastModifiedDateTime": None, "errorCode": "PackageManagerFailure", "errorMessage": "repo unreachable"},
    ]
    outcomes = _rows_to_outcomes(rows)
    assert outcomes == [
        ("/subscriptions/s/.../vm-1", "Succeeded", "2026-09-26T04:00:00Z", "2026-09-26T04:12:00Z", None, None),
        ("/subscriptions/s/.../vm-2", "Unknown", None, None, None, None),  # a missing status defaults to "Unknown", not blank
        ("/subscriptions/s/.../vm-3", "Failed", "2026-09-26T04:00:00Z", None, "PackageManagerFailure", "repo unreachable"),
    ]


def test_rows_to_outcomes_dedupes_a_vm_touched_twice_keeping_the_latest():
    """Found in review: a VM with more than one patch-result row in the
    same window (a retried install, overlapping maintenance configs)
    used to produce two entries for the same vm_id, inflating the
    report's totals. The query itself now dedupes via `summarize
    arg_max(startDateTime, *) by vmId` - this is the client-side defense
    in depth under that, proving the fallback actually keeps the later
    row, not an arbitrary one."""
    rows = [
        {"vmId": "/subscriptions/s/.../vm-1", "status": "Failed", "startDateTime": "2026-09-26T04:00:00Z", "lastModifiedDateTime": "2026-09-26T04:05:00Z"},
        {"vmId": "/subscriptions/s/.../vm-1", "status": "Succeeded", "startDateTime": "2026-09-26T05:30:00Z", "lastModifiedDateTime": "2026-09-26T05:35:00Z"},
        {"vmId": "/subscriptions/s/.../vm-2", "status": "Succeeded", "startDateTime": "2026-09-26T04:00:00Z", "lastModifiedDateTime": "2026-09-26T04:02:00Z"},
    ]
    outcomes = _rows_to_outcomes(rows)
    assert len(outcomes) == 2
    vm_1 = next(o for o in outcomes if o[0] == "/subscriptions/s/.../vm-1")
    assert vm_1 == ("/subscriptions/s/.../vm-1", "Succeeded", "2026-09-26T05:30:00Z", "2026-09-26T05:35:00Z", None, None)


def test_identity_from_vm_id_parses_the_standard_arm_shape():
    identity = _identity_from_vm_id(
        "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-prod"
        "/providers/Microsoft.Compute/virtualMachines/vm-app-01"
    )
    assert identity == {
        "subscription_id": "11111111-2222-3333-4444-555555555555",
        "resource_group": "rg-prod",
        "vm_name": "vm-app-01",
    }


def test_identity_from_vm_id_returns_none_for_a_non_standard_id():
    assert _identity_from_vm_id("not-an-arm-id") is None
    assert _identity_from_vm_id("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/disks/disk-1") is None


def test_status_from_raw_maps_the_four_buckets():
    assert _status_from_raw("Succeeded") == InstallationStatus.SUCCEEDED
    assert _status_from_raw("succeeded") == InstallationStatus.SUCCEEDED  # case-insensitive
    assert _status_from_raw("Unknown") == InstallationStatus.UNRESPONSIVE_OR_SHUTDOWN
    assert _status_from_raw("") == InstallationStatus.UNRESPONSIVE_OR_SHUTDOWN
    assert _status_from_raw(None) == InstallationStatus.UNRESPONSIVE_OR_SHUTDOWN
    assert _status_from_raw("Failed") == InstallationStatus.FAILED
    assert _status_from_raw("CompletedWithWarnings") == InstallationStatus.FAILED  # folded into Failed, no 5th bucket


def test_guest_log_path_linux_has_no_version_subdirectory():
    """Found in review 2026-10-16: the Linux patch extension's real log
    directory (/var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/)
    is flat and sequence-numbered, not version-rooted like Windows - the
    previous hint invented a `.../{version}/core.log` shape that doesn't
    exist on a real guest. extension_version must not appear in the
    Linux path at all (unlike Windows, where it's load-bearing)."""
    path = _guest_log_path(OSFamily.LINUX, extension_version="1.6.71")
    assert "1.6.71" not in path
    assert path.startswith("/var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/")
    assert "core.log" in path


def test_guest_log_path_windows_substitutes_the_real_version():
    path = _guest_log_path(OSFamily.WINDOWS, extension_version="1.5.71")
    assert path == r"C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\1.5.71\WindowsPatchExtension.log"


def test_guest_log_path_windows_falls_back_when_version_not_collected():
    path = _guest_log_path(OSFamily.WINDOWS, extension_version=None)
    assert "not collected for this machine" in path


def test_guest_log_path_unknown_os_is_none():
    assert _guest_log_path(OSFamily.UNKNOWN) is None


# ── Repository save/load round trip ────────────────────────────────────────────

@pytest.fixture
def session_factory():
    engine = make_engine("sqlite:///:memory:")
    return make_session_factory(engine)


def test_save_and_load_installation_report_round_trip(session_factory):
    from culprit.db import repository
    from culprit.db.models import RunStage
    from culprit.models.installation_report import InstallationOutcomeRow
    from culprit.models.patch_run import PatchRun, TriggerMode

    run_id = "run-1"
    with session_factory() as session:
        repository.save_run(
            session,
            PatchRun(run_id=run_id, maintenance_configuration_id="mc-1", subscription_id="sub-1",
                      scope_name="scope-a", started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=10,
                      trigger_mode=TriggerMode.AD_HOC),
            stage=RunStage.STARTED,
        )
        rows = [
            InstallationOutcomeRow(vm_id="vm-1", vm_name="vm-1", status=InstallationStatus.SUCCEEDED, subscription_id="sub-1", resource_group="rg-1"),
            InstallationOutcomeRow(vm_id="vm-2", vm_name="vm-2", status=InstallationStatus.FAILED, subscription_id="sub-1", resource_group="rg-1", error_code="PackageManagerFailure", cause_family=None),
        ]
        repository.save_installation_report(session, run_id, rows, excluded_count=3)

    with session_factory() as session:
        loaded = repository.load_installation_report(session, run_id)
    assert loaded is not None
    assert loaded.succeeded_count == 1
    assert loaded.failed_count == 1
    assert loaded.excluded_count == 3
    assert loaded.total_count == 5  # 2 rows + 3 excluded
    assert loaded.rows[1].error_code == "PackageManagerFailure"


def test_build_installation_report_prefers_the_failed_bundle_over_a_duplicate_non_failure_row():
    """Found in review: build_installation_report's own de-dup only
    filters non_failure_rows against failed_bundles' vm_ids - this proves
    it actually works, since the two report tests' demo data happen to
    use disjoint vm-name namespaces and never exercise it. A machine
    whose vm_id appears in BOTH sources (both discover_all_patch_outcomes
    and discover_failed_machines read the same window, so this is a real,
    not hypothetical, overlap) must end up as exactly one row - the
    richer, RCA-eligible Failed one, not the bulk-query's bare status."""
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode
    from culprit.models.rca import CausalStep, RCAResult, RemediationPlaybook, RemediationStep, ResultOrigin, RiskLevel
    from culprit.models.report import ClusterReportEntry, FleetReport
    from culprit.models.taxonomy import CauseFamily

    vm_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"
    run = PatchRun(run_id="run-1", maintenance_configuration_id="mc-1", subscription_id="s", scope_name="scope-a",
                   started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=10, trigger_mode=TriggerMode.AD_HOC)

    bundle = EvidenceBundle(
        run_id="run-1",
        machine=MachineIdentity(vm_id=vm_id, vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX),
        outcome=PatchOutcome(status="Failed", error_code="PackageManagerFailure"),
        collection_started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    cluster = Cluster(
        cluster_id="c1", run_id="run-1", cluster_key="key:c1",
        fingerprint=Fingerprint(error_code_normalized="x", os_family=OSFamily.LINUX, failing_target=""),
        members=[ClusterMember(vm_id=vm_id, vm_name="vm-1", resource_group="rg", subscription_id="s")],
        representative_vm_id=vm_id,
    )
    result = RCAResult(
        cluster_id="c1", origin=ResultOrigin.RULE_ENGINE, cause_family=CauseFamily.CAPACITY, title="Disk full", confidence=0.9,
        causal_chain=[CausalStep(order=1, statement="x", evidence_refs=["r"])],
        remediation=RemediationPlaybook(immediate_fix=[RemediationStep(order=1, instruction="x")], immediate_risk=RiskLevel.LOW),
    )
    fleet_report = FleetReport(run=run, total_machines=10, total_failed=1, total_clusters=1,
                                entries=[ClusterReportEntry(cluster=cluster, result=result)])

    non_failure_rows = [
        {"vm_id": vm_id, "vm_name": "vm-1", "resource_group": "rg", "subscription_id": "s",
         "status": "Succeeded", "started_at": None, "ended_at": None},  # same vm_id - must be dropped
        {"vm_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-2",
         "vm_name": "vm-2", "resource_group": "rg", "subscription_id": "s",
         "status": "Succeeded", "started_at": None, "ended_at": None},
    ]

    report = build_installation_report(run, [bundle], fleet_report, non_failure_rows, excluded_count=0)

    assert len(report.rows) == 2
    vm_1_row = next(r for r in report.rows if r.vm_id == vm_id)
    assert vm_1_row.status.value == "failed"  # the richer failed_bundles row won, not the duplicate "Succeeded"
    assert vm_1_row.error_code == "PackageManagerFailure"
    assert vm_1_row.cause_family == CauseFamily.CAPACITY
    vm_2_row = next(r for r in report.rows if r.vm_name == "vm-2")
    assert vm_2_row.status.value == "succeeded"


def test_build_installation_report_dedup_is_case_insensitive():
    """Found 2026-10-16 (a real tenant run, 3 of 160 failed - nowhere near
    the RCA cap): discover_failed_machines's vm_id comes from the
    Resources table's own `id` column, while non_failure_rows's vm_id is
    derived from the *different* patchinstallationresources table's own
    `id` (discovery.py::_ALL_PATCH_RESULTS_QUERY). Azure resource IDs are
    documented case-insensitive for comparison, but the previous dedup
    check was a bare, case-sensitive set-membership test - a casing
    difference between these two Resource Graph surfaces (a real,
    documented Azure RP inconsistency, not something this codebase
    controls) let the same machine appear twice: once correctly
    diagnosed via failed_bundles, once as a duplicate "Not yet diagnosed"
    row from non_failure_rows. Same fixture shape as the sibling test
    above, except the non_failure_rows entry's vm_id differs only in
    case from the failed_bundles one."""
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode
    from culprit.models.rca import CausalStep, RCAResult, ResultOrigin
    from culprit.models.report import ClusterReportEntry, FleetReport
    from culprit.models.taxonomy import CauseFamily

    vm_id = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm-1"
    vm_id_different_case = "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-1"
    run = PatchRun(run_id="run-1", maintenance_configuration_id="mc-1", subscription_id="s", scope_name="scope-a",
                   started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=10, trigger_mode=TriggerMode.AD_HOC)

    bundle = EvidenceBundle(
        run_id="run-1",
        machine=MachineIdentity(vm_id=vm_id, vm_name="vm-1", resource_group="RG", subscription_id="S", os_family=OSFamily.LINUX),
        outcome=PatchOutcome(status="Failed", error_code="PackageManagerFailure"),
        collection_started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    cluster = Cluster(
        cluster_id="c1", run_id="run-1", cluster_key="key:c1",
        fingerprint=Fingerprint(error_code_normalized="x", os_family=OSFamily.LINUX, failing_target=""),
        members=[ClusterMember(vm_id=vm_id, vm_name="vm-1", resource_group="RG", subscription_id="S")],
        representative_vm_id=vm_id,
    )
    result = RCAResult(
        cluster_id="c1", origin=ResultOrigin.RULE_ENGINE, cause_family=CauseFamily.CAPACITY, title="Disk full", confidence=0.9,
        causal_chain=[CausalStep(order=1, statement="x", evidence_refs=["r"])],
    )
    fleet_report = FleetReport(run=run, total_machines=10, total_failed=1, total_clusters=1,
                                entries=[ClusterReportEntry(cluster=cluster, result=result)])

    non_failure_rows = [
        {"vm_id": vm_id_different_case, "vm_name": "vm-1", "resource_group": "rg", "subscription_id": "s",
         "status": "Failed", "started_at": None, "ended_at": None},  # same VM, different case - must still be dropped
    ]

    report = build_installation_report(run, [bundle], fleet_report, non_failure_rows, excluded_count=0)

    assert len(report.rows) == 1
    assert report.rows[0].cause_family == CauseFamily.CAPACITY


def test_build_installation_report_carries_raw_error_detail_for_a_failed_row_beyond_the_rca_cap():
    """Found in review: discover_failed_machines caps at
    _MAX_MACHINES_PER_RUN (200), but the bulk full-fleet query has no
    such cap - a fleet with more than 200 concurrent failures in one
    window has some genuinely Failed machines appear only in
    non_failure_rows, never in failed_bundles (never RCA'd). Before this
    fix those rows carried no error_code/error_message at all - a
    "Failed" row with nothing else to show, on exactly the large-fleet
    case this report exists for. Proves the bulk query's own raw error
    now survives into the row even with zero RCA."""
    from culprit.models.patch_run import PatchRun, TriggerMode
    from culprit.models.report import FleetReport

    run = PatchRun(run_id="run-1", maintenance_configuration_id="mc-1", subscription_id="s", scope_name="scope-a",
                   started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=500, trigger_mode=TriggerMode.AD_HOC)
    fleet_report = FleetReport(run=run, total_machines=500, total_failed=0, total_clusters=0, entries=[])

    non_failure_rows = [{
        "vm_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-201",
        "vm_name": "vm-201", "resource_group": "rg", "subscription_id": "s",
        "status": "Failed", "started_at": None, "ended_at": None,
        "error_code": "PackageManagerFailure", "error_message": "repo unreachable",
    }]

    report = build_installation_report(run, [], fleet_report, non_failure_rows, excluded_count=0)

    assert len(report.rows) == 1
    row = report.rows[0]
    assert row.status.value == "failed"
    assert row.error_code == "PackageManagerFailure"
    assert row.error_message == "repo unreachable"
    assert row.cause_family is None  # never reached RCA - no diagnosis to show, but the raw error is there


def test_fleet_report_hides_the_installation_report_link_when_none_was_built():
    """Found in review: the "View installation report" link on the Fleet
    Report page was unconditional - a run that predates this feature, or
    one where the best-effort build silently failed, still showed a
    working-looking link that 404'd with a raw JSON error, not a styled
    page. Proves render_fleet_report_html actually hides it."""
    from culprit.models.patch_run import PatchRun, TriggerMode
    from culprit.models.report import FleetReport
    from culprit.reporting.render import render_fleet_report_html

    run = PatchRun(run_id="run-1", maintenance_configuration_id="mc-1", subscription_id="s", scope_name="scope-a",
                   started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=10, trigger_mode=TriggerMode.AD_HOC)
    report = FleetReport(run=run, total_machines=10, total_failed=0, total_clusters=0, entries=[])

    html_without = render_fleet_report_html(report, installation_report_available=False)
    assert "installation-report.html" not in html_without

    html_with = render_fleet_report_html(report, installation_report_available=True)
    assert "installation-report.html" in html_with


def test_fleet_report_shows_the_email_widget_based_on_email_configured_not_smtp_specifically():
    """Found by review 2026-10-22: render_fleet_report_html's gate for the
    "Email report" widget used to be named (and only ever fed from)
    SMTP's own configured-state - routes_runs.py::get_report_html now
    computes this from whichever email method is actually active (see
    that route's own comment), so this parameter must work as a generic
    "is email configured at all" flag, not implicitly assume SMTP."""
    from culprit.models.patch_run import PatchRun, TriggerMode
    from culprit.models.report import FleetReport
    from culprit.reporting.render import render_fleet_report_html

    run = PatchRun(run_id="run-1", maintenance_configuration_id="mc-1", subscription_id="s", scope_name="scope-a",
                   started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=10, trigger_mode=TriggerMode.AD_HOC)
    report = FleetReport(run=run, total_machines=10, total_failed=0, total_clusters=0, entries=[])

    # The JS at the bottom of the page references ".email-report-widget"
    # (querySelectorAll) regardless of whether the Jinja {% if %} rendered
    # the div itself - checking for the actual element's opening tag, not
    # the bare class name, is what actually proves the widget is gone.
    html_without = render_fleet_report_html(report, email_configured=False)
    assert '<div class="email-report-widget' not in html_without

    html_with = render_fleet_report_html(report, email_configured=True, default_recipients=["ops@example.com"])
    assert '<div class="email-report-widget' in html_with
    assert "ops@example.com" in html_with


def test_load_installation_report_returns_none_when_never_built(session_factory):
    from culprit.db import repository
    from culprit.db.models import RunStage
    from culprit.models.patch_run import PatchRun, TriggerMode

    with session_factory() as session:
        repository.save_run(
            session,
            PatchRun(run_id="run-no-ir", maintenance_configuration_id="mc-1", subscription_id="sub-1",
                      scope_name="scope-a", started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=10,
                      trigger_mode=TriggerMode.AD_HOC),
            stage=RunStage.STARTED,
        )
        assert repository.load_installation_report(session, "run-no-ir") is None


# ── Demo route end to end ──────────────────────────────────────────────────────

@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module
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

    return TestClient(app, raise_server_exceptions=False)


def test_installation_report_404_for_unknown_run(client):
    resp = client.get("/runs/nope/installation-report")
    assert resp.status_code == 404
    resp = client.get("/runs/nope/installation-report.html")
    assert resp.status_code == 404


def test_demo_run_builds_a_consistent_installation_report(client):
    from culprit.demo.generate_scenario import FAILED_COUNT, TOTAL_MACHINES

    resp = client.post("/runs/demo")
    assert resp.status_code == 200
    run_id = resp.json()["run"]["run_id"]

    ir = client.get(f"/runs/{run_id}/installation-report").json()
    assert ir["excluded_count"] > 0
    total = len(ir["rows"]) + ir["excluded_count"]
    assert total == TOTAL_MACHINES

    failed_rows = [r for r in ir["rows"] if r["status"] == "failed"]
    assert len(failed_rows) == FAILED_COUNT
    # Every failed row reached RCA in the demo (the scripted agent always
    # resolves) - this is what actually proves the join against
    # fleet_report.entries worked, not just that rows exist.
    assert all(r["cause_family"] for r in failed_rows)
    assert all(r["rca_confidence"] is not None for r in failed_rows)

    succeeded_rows = [r for r in ir["rows"] if r["status"] == "succeeded"]
    assert len(succeeded_rows) > 0
    assert succeeded_rows[0]["cause_family"] is None  # no RCA for a machine that never failed

    unresponsive_rows = [r for r in ir["rows"] if r["status"] == "unresponsive_or_shutdown"]
    assert len(unresponsive_rows) > 0


def test_installation_report_html_explains_a_failed_row_with_no_cause_family():
    """A FAILED row that never went through the deep-RCA pipeline (today
    this only ever happens via non_failure_rows - see
    build_installation_report's own docstring and installation_report.py's
    comment on the RCA cap / discovery-timing-gap case) used to render a
    flat, dead-end "Not yet diagnosed" with no explanation and no next
    step. Must now explain why and point at the actual fix (re-run live
    analysis), reusing this page's existing info-icon-tooltip convention
    (the "Excluded (i)" tile)."""
    from culprit.models.installation_report import InstallationOutcomeRow, InstallationReport
    from culprit.models.patch_run import PatchRun, TriggerMode
    from culprit.reporting.render import render_installation_report_html

    run = PatchRun(run_id="run-1", maintenance_configuration_id="mc-1", subscription_id="s", scope_name="scope-a",
                   started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=1, trigger_mode=TriggerMode.AD_HOC)
    row = InstallationOutcomeRow(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", status=InstallationStatus.FAILED, subscription_id="s", resource_group="rg",
    )
    report = InstallationReport(run=run, rows=[row], excluded_count=0)

    html = render_installation_report_html(report)
    assert "Not included in this scan" in html
    assert "Run live analysis again" in html
    assert "Not yet diagnosed" not in html


def test_installation_report_html_renders_all_four_categories(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    html = client.get(f"/runs/{run_id}/installation-report.html").text
    assert "Successful" in html
    assert "Unresponsive or Shutdown" in html
    assert "Excluded" in html
    # A raw-error-detail block for at least one failed row.
    assert "Raw error detail" in html
    # The derived-count explanation for Excluded, not silently omitted.
    assert "derived count" in html.lower()


def test_fleet_report_links_to_installation_report_and_back(client):
    resp = client.post("/runs/demo")
    run_id = resp.json()["run"]["run_id"]

    fleet_html = client.get(f"/runs/{run_id}/report.html").text
    assert "installation-report.html" in fleet_html

    ir_html = client.get(f"/runs/{run_id}/installation-report.html").text
    assert "report.html" in ir_html
