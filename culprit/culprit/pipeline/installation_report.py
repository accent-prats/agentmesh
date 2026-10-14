"""Builds the Patch Installation Report (models/installation_report.py) -
shared by the live path (pipeline/live_run.py::execute_live_run) and the
demo path (api/routes_runs.py::trigger_demo_run) so both assemble this
exactly the same way from that point on.
"""
from __future__ import annotations

from culprit.models.evidence import EvidenceBundle, OSFamily
from culprit.models.installation_report import InstallationOutcomeRow, InstallationReport, InstallationStatus
from culprit.models.report import FleetReport


def _status_from_raw(raw: str) -> InstallationStatus:
    """Maps a raw Azure/collector status string onto this report's 4
    buckets. "Unresponsive or Shutdown" is this report's own label for
    Azure's native `Unknown` (or an outright missing) status - the
    working assumption stated in models/installation_report.py's own
    docstring. Anything else non-succeeded (Failed,
    CompletedWithWarnings, InProgress at report-generation time, ...) is
    folded into Failed - the original report this mirrors has no 5th
    bucket for those, and a stalled/incomplete result is as actionable
    as an outright failure."""
    lowered = (raw or "").strip().lower()
    if lowered == "succeeded":
        return InstallationStatus.SUCCEEDED
    if lowered in ("unknown", ""):
        return InstallationStatus.UNRESPONSIVE_OR_SHUTDOWN
    return InstallationStatus.FAILED


def _guest_log_path(os_family: OSFamily) -> str | None:
    """The well-known Azure Update Manager guest-log location for this
    machine's OS family - stated as a plain convention (the
    extension-version path segment is genuinely unknown to Culprit, never
    independently collected), not a path Culprit has verified exists on
    this specific guest. See models/installation_report.py's own
    docstring on why this is phrased this way."""
    if os_family == OSFamily.LINUX:
        return "/var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/<extension-version>/core.log"
    if os_family == OSFamily.WINDOWS:
        return r"C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\<extension-version>\WindowsPatchExtension.log"
    return None


def build_installation_report(
    run, failed_bundles: list[EvidenceBundle], fleet_report: FleetReport,
    non_failure_rows: list[dict], excluded_count: int,
) -> InstallationReport:
    """`failed_bundles` is the same list `Pipeline.run()` was already
    given - their own `PatchOutcome.status`/`error_code`/`error_message`
    is used directly (these were collected per-machine, real data),
    enriched with Culprit's RCA via a vm_id lookup built from
    `fleet_report.entries` (no new RCA logic, just a join).
    `non_failure_rows` is whichever bulk source the caller already
    resolved - plain dicts with vm_id/vm_name/subscription_id/
    resource_group/status/started_at/ended_at (live:
    discovery.py::discover_all_patch_outcomes_with_identity; demo:
    demo/generate_scenario.py::fabricate_non_failure_outcomes - the same
    shape from both, so this is the one place that converts either into
    an `InstallationOutcomeRow`, not two). Filtered here to drop any
    vm_id already covered by `failed_bundles`, since both sources read
    the same window and could otherwise double-count a machine."""
    rca_by_vm_id = {}
    for entry in fleet_report.entries:
        for member in entry.cluster.members:
            rca_by_vm_id[member.vm_id] = (entry.cluster.cluster_id, entry.result.cause_family, entry.result.title, entry.result.confidence)

    rows: list[InstallationOutcomeRow] = []
    for bundle in failed_bundles:
        cluster_id, cause_family, title, confidence = rca_by_vm_id.get(bundle.machine.vm_id, (None, None, None, None))
        rows.append(InstallationOutcomeRow(
            vm_id=bundle.machine.vm_id, vm_name=bundle.machine.vm_name,
            status=_status_from_raw(bundle.outcome.status),
            subscription_id=bundle.machine.subscription_id, resource_group=bundle.machine.resource_group,
            started_at=bundle.outcome.started_at, ended_at=bundle.outcome.ended_at,
            error_code=bundle.outcome.error_code, error_message=bundle.outcome.error_message,
            log_path=_guest_log_path(bundle.machine.os_family),
            cause_family=cause_family, rca_title=title, rca_confidence=confidence, cluster_id=cluster_id,
        ))

    covered_vm_ids = {b.machine.vm_id for b in failed_bundles}
    for r in non_failure_rows:
        if r["vm_id"] in covered_vm_ids:
            continue
        rows.append(InstallationOutcomeRow(
            vm_id=r["vm_id"], vm_name=r["vm_name"], status=_status_from_raw(r["status"]),
            subscription_id=r["subscription_id"], resource_group=r["resource_group"],
            started_at=r.get("started_at"), ended_at=r.get("ended_at"),
        ))

    return InstallationReport(run=run, rows=rows, excluded_count=excluded_count)
