"""Build a FleetReport from a completed pipeline run."""
from __future__ import annotations

from culprit.models.evidence import EvidenceBundle
from culprit.models.report import ClusterReportEntry, FleetReport, MachineRow
from culprit.models.taxonomy import CauseFamily
from culprit.pipeline.orchestrator import PipelineOutput


def build_fleet_report(output: PipelineOutput, total_machines: int, bundles: list[EvidenceBundle]) -> FleetReport:
    """`bundles` is the same `failed_bundles` list already passed to
    `Pipeline.run()` - needed here too so `machine_rows` (the fleet
    report's per-machine table, see models/report.py::MachineRow) can be
    built straight from each bundle's own `outcome`, the in-memory
    equivalent of the batch `MachineOutcomeRecord` query
    `db/repository.py::_load_fleet_report_core` runs for a report
    reconstructed from storage. Found 2026-10-13 reviewing the table this
    function's own caller (demo/run_demo.py, the actual event-demo script)
    writes to a static HTML file: this is a second, independent
    FleetReport construction path, and it silently produced an empty
    machine_rows - no error, just a quietly missing table - until this
    fix."""
    entries = [
        ClusterReportEntry(
            cluster=d.cluster,
            result=d.result,
            recurrence_badge=d.recurrence.badge,
            consecutive_cycles=d.recurrence.consecutive_cycles,
        )
        for d in output.diagnosed
    ]
    entries.sort(key=lambda e: -e.cluster.size)

    total_failed = sum(e.cluster.size for e in entries)
    unresolved = sum(e.cluster.size for e in entries if e.result.cause_family == CauseFamily.UNRESOLVED)
    repeat_offenders = sum(1 for e in entries if e.recurrence_badge)

    bundle_by_vm = {b.machine.vm_id: b for b in bundles}
    machine_rows = []
    for e in entries:
        has_immediate_fix = bool(e.result.remediation and e.result.remediation.immediate_fix)
        for m in e.cluster.members:
            bundle = bundle_by_vm.get(m.vm_id)
            has_extension_finding = bool(
                bundle is not None
                and any(f.get("status") in ("error", "warning") for f in bundle.patch_extension_status)
            )
            has_azure_error_detail = bool(bundle is not None and bundle.outcome.error_details)
            machine_rows.append(
                MachineRow(
                    vm_id=m.vm_id,
                    vm_name=m.vm_name,
                    cluster_id=e.cluster.cluster_id,
                    cause_family=e.result.cause_family,
                    title=e.result.title,
                    confidence=e.result.confidence,
                    is_actionable=e.result.is_actionable,
                    has_immediate_fix=has_immediate_fix,
                    outcome=bundle.outcome if bundle is not None else None,
                    has_extension_finding=has_extension_finding,
                    has_azure_error_detail=has_azure_error_detail,
                )
            )

    return FleetReport(
        run=output.run,
        total_machines=total_machines,
        total_failed=total_failed,
        total_clusters=len(entries),
        entries=entries,
        machine_rows=machine_rows,
        unresolved_count=unresolved,
        repeat_offender_count=repeat_offenders,
    )
