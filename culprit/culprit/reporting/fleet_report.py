"""Build a FleetReport from a completed pipeline run."""
from __future__ import annotations

from culprit.models.report import ClusterReportEntry, FleetReport
from culprit.models.taxonomy import CauseFamily
from culprit.pipeline.orchestrator import PipelineOutput


def build_fleet_report(output: PipelineOutput, total_machines: int) -> FleetReport:
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

    return FleetReport(
        run=output.run,
        total_machines=total_machines,
        total_failed=total_failed,
        total_clusters=len(entries),
        entries=entries,
        unresolved_count=unresolved,
        repeat_offender_count=repeat_offenders,
    )
