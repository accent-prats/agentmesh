"""reporting/render.py::_cluster_date_ranges - the Fleet Report cluster
card's "patched {date range}" label.

Exists because a live/scheduled run's discovery window is a time-window
heuristic standing in for "one maintenance run" (pipeline/discovery.py's
own docstring), not a resolved Azure maintenance-run boundary - the
scheduled default window is 8 days, an ad hoc run can be configured up to
30 - so one Culprit run routinely sweeps machines from several distinct
real Azure maintenance executions together. A team reviewing a run
reported confusion seeing multiple cluster cards with the identical RCA
title and different machine sets, unsure whether that's the same issue
duplicated or genuinely separate causes. Clustering is purely structural
(fingerprint.py: error code/OS family/failing target/preconditions,
never time, never the title text), so two clusters CAN legitimately share
a title while being wholly unrelated - the date range resolves the
ambiguity either way, with zero new Azure query (it's built entirely from
PatchOutcome.started_at, already collected and persisted per machine)."""
from __future__ import annotations

from datetime import date, datetime, timezone

from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
from culprit.models.evidence import OSFamily, PatchOutcome
from culprit.models.patch_run import PatchRun, TriggerMode
from culprit.models.rca import CausalStep, RCAResult, ResultOrigin
from culprit.models.report import ClusterReportEntry, FleetReport, MachineRow
from culprit.models.taxonomy import CauseFamily
from culprit.reporting.render import _cluster_date_ranges, render_fleet_report_html


def _row(vm_id: str, cluster_id: str, started_at: datetime | None) -> MachineRow:
    return MachineRow(
        vm_id=vm_id, vm_name=vm_id, cluster_id=cluster_id, cause_family=CauseFamily.SOURCE_ENTITLEMENT,
        title="t", confidence=0.9, is_actionable=False, has_immediate_fix=False,
        outcome=PatchOutcome(status="Failed", started_at=started_at) if started_at else None,
    )


def _report(machine_rows: list[MachineRow]) -> FleetReport:
    return FleetReport(
        run=PatchRun(
            run_id="run-1", maintenance_configuration_id="cfg", subscription_id="s",
            scope_name="test", started_at=datetime.now(timezone.utc), total_machines=len(machine_rows),
            trigger_mode=TriggerMode.AD_HOC,
        ),
        total_machines=len(machine_rows), total_failed=len(machine_rows), total_clusters=1,
        machine_rows=machine_rows,
    )


def test_a_single_days_worth_of_machines_yields_one_date_both_ends():
    report = _report([
        _row("vm-1", "cluster-a", datetime(2026, 10, 10, 2, 0, tzinfo=timezone.utc)),
        _row("vm-2", "cluster-a", datetime(2026, 10, 10, 6, 0, tzinfo=timezone.utc)),
    ])
    ranges = _cluster_date_ranges(report)
    assert ranges["cluster-a"] == (date(2026, 10, 10), date(2026, 10, 10))


def test_machines_spanning_several_days_yield_the_full_range():
    report = _report([
        _row("vm-1", "cluster-b", datetime(2026, 10, 8, tzinfo=timezone.utc)),
        _row("vm-2", "cluster-b", datetime(2026, 10, 13, tzinfo=timezone.utc)),
        _row("vm-3", "cluster-b", datetime(2026, 10, 10, tzinfo=timezone.utc)),
    ])
    ranges = _cluster_date_ranges(report)
    assert ranges["cluster-b"] == (date(2026, 10, 8), date(2026, 10, 13))


def test_machines_with_no_outcome_are_excluded_not_crashed_on():
    report = _report([
        _row("vm-1", "cluster-c", None),
        _row("vm-2", "cluster-c", datetime(2026, 10, 10, tzinfo=timezone.utc)),
    ])
    ranges = _cluster_date_ranges(report)
    assert ranges["cluster-c"] == (date(2026, 10, 10), date(2026, 10, 10))


def test_a_cluster_with_no_dated_machines_at_all_has_no_entry():
    report = _report([_row("vm-1", "cluster-d", None)])
    ranges = _cluster_date_ranges(report)
    assert "cluster-d" not in ranges


def test_each_cluster_is_computed_independently():
    report = _report([
        _row("vm-1", "cluster-e", datetime(2026, 10, 1, tzinfo=timezone.utc)),
        _row("vm-2", "cluster-f", datetime(2026, 10, 20, tzinfo=timezone.utc)),
    ])
    ranges = _cluster_date_ranges(report)
    assert ranges["cluster-e"] == (date(2026, 10, 1), date(2026, 10, 1))
    assert ranges["cluster-f"] == (date(2026, 10, 20), date(2026, 10, 20))


def _entry(cluster_id: str) -> ClusterReportEntry:
    member = ClusterMember(vm_id="vm-1", vm_name="vm-1")
    cluster = Cluster(
        cluster_id=cluster_id, run_id="run-1", cluster_key="key-1",
        fingerprint=Fingerprint(error_code_normalized="x", os_family=OSFamily.LINUX, failing_target=""),
        members=[member], representative_vm_id="vm-1",
    )
    result = RCAResult(
        cluster_id=cluster_id, origin=ResultOrigin.RULE_ENGINE, cause_family=CauseFamily.SOURCE_ENTITLEMENT,
        title="Update source unreachable during the window",
        causal_chain=[CausalStep(order=1, statement="repo unreachable", evidence_refs=["ref-1"])],
        confidence=0.85,
    )
    return ClusterReportEntry(cluster=cluster, result=result)


def test_fleet_report_shows_a_single_date_when_every_machine_shares_one():
    report = _report([_row("vm-1", "cluster-a", datetime(2026, 10, 10, tzinfo=timezone.utc))])
    report = report.model_copy(update={"entries": [_entry("cluster-a")]})
    html = render_fleet_report_html(report)
    assert "patched 2026-10-10" in html
    assert "&ndash;" not in html  # single date - no range dash


def test_fleet_report_shows_a_range_when_machines_span_multiple_days():
    report = _report([
        _row("vm-1", "cluster-a", datetime(2026, 10, 8, tzinfo=timezone.utc)),
        _row("vm-2", "cluster-a", datetime(2026, 10, 13, tzinfo=timezone.utc)),
    ])
    report = report.model_copy(update={"entries": [_entry("cluster-a")]})
    html = render_fleet_report_html(report)
    assert "patched 2026-10-08" in html
    assert "2026-10-13" in html


def test_fleet_report_omits_the_date_label_when_no_machine_has_a_dated_outcome():
    report = _report([_row("vm-1", "cluster-a", None)])
    report = report.model_copy(update={"entries": [_entry("cluster-a")]})
    html = render_fleet_report_html(report)
    assert "patched" not in html
