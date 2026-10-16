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


def _guest_log_path(os_family: OSFamily, extension_version: str | None = None) -> str | None:
    """The Azure Update Manager guest-log location for this machine's OS
    family. When `extension_version` was actually resolved by a real
    guest collection (guest_windows.py/guest_linux.py's EXT_VERSION,
    threaded through each patch_extension_status finding), this is a real,
    verified path on that specific guest - substituted in below. Otherwise
    it falls back to the generic per-OS-family convention, worded as a
    hint rather than a resolved fact - found confusing 2026-10-15: the
    previous version always showed the literal, unsubstituted
    `<extension-version>` placeholder even when nothing was collected,
    which reads as a broken path rather than a convention a human could
    still go look up manually.

    The Linux branch has no version-subdirectory component - found in
    review 2026-10-16, while adding collectors/guest_linux.py's EXT_CORE_LOG
    section for this exact file: unlike the Windows patch extension's log
    (versioned, `.../WindowsPatchExtension\\<version>\\WindowsPatchExtension.log`),
    the Linux patch extension's own log directory is flat and not
    version-rooted - Microsoft's docs and the real collector both target
    `/var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/<sequence-
    number>.core.log`, a sequence-numbered file directly under that
    directory. The previous version of this hint invented a
    `.../{version}/core.log` shape that doesn't exist on a real guest -
    anyone following it by hand would have looked in a directory that
    was never there."""
    if os_family == OSFamily.LINUX:
        return "/var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/<sequence-number>.core.log (use the most recent by file time)"
    if os_family == OSFamily.WINDOWS:
        version = extension_version or "<extension-version> (version not collected for this machine)"
        return rf"C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\{version}\WindowsPatchExtension.log"
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
        resolved_version = next(
            (f.get("extension_version") for f in bundle.patch_extension_status if f.get("extension_version")),
            None,
        )
        rows.append(InstallationOutcomeRow(
            vm_id=bundle.machine.vm_id, vm_name=bundle.machine.vm_name,
            status=_status_from_raw(bundle.outcome.status),
            subscription_id=bundle.machine.subscription_id, resource_group=bundle.machine.resource_group,
            started_at=bundle.outcome.started_at, ended_at=bundle.outcome.ended_at,
            error_code=bundle.outcome.error_code, error_message=bundle.outcome.error_message,
            error_details=bundle.outcome.error_details,
            log_path=_guest_log_path(bundle.machine.os_family, resolved_version),
            cause_family=cause_family, rca_title=title, rca_confidence=confidence, cluster_id=cluster_id,
        ))

    # .lower() on both sides - found 2026-10-16: discover_failed_machines's
    # vm_id comes from the Resources table's own `id` column, while
    # non_failure_rows's vm_id is derived from the *different*
    # patchinstallationresources table's own `id` (discovery.py's
    # _ALL_PATCH_RESULTS_QUERY). Both represent the same VM, but Azure
    # resource IDs are only documented case-*insensitive* for comparison -
    # a bare, case-sensitive set-membership check here let a casing
    # mismatch between those two Resource Graph surfaces silently fail
    # open, showing the same machine twice (once correctly diagnosed via
    # failed_bundles, once as a duplicate "Not yet diagnosed" row here).
    covered_vm_ids = {b.machine.vm_id.lower() for b in failed_bundles}
    for r in non_failure_rows:
        if r["vm_id"].lower() in covered_vm_ids:
            continue
        # error_code/error_message come straight from the bulk query
        # (discovery.py::_ALL_PATCH_RESULTS_QUERY now projects them) -
        # found in review: a genuinely Failed machine beyond
        # discover_failed_machines's own _MAX_MACHINES_PER_RUN cap (a
        # large-fleet run with >200 concurrent failures, exactly the
        # case this report exists for) would otherwise reach this branch
        # with no diagnostic information at all, not even the raw Azure
        # error - a "Failed" row with nothing else to show. There's no
        # log_path here (unlike the failed_bundles branch above) since
        # the bulk query has no OS family to pick a convention path from.
        rows.append(InstallationOutcomeRow(
            vm_id=r["vm_id"], vm_name=r["vm_name"], status=_status_from_raw(r["status"]),
            subscription_id=r["subscription_id"], resource_group=r["resource_group"],
            started_at=r.get("started_at"), ended_at=r.get("ended_at"),
            error_code=r.get("error_code"), error_message=r.get("error_message"),
        ))

    return InstallationReport(run=run, rows=rows, excluded_count=excluded_count)
