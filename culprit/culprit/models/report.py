"""The fleet-level report model (proposal Section 8: three artefacts, this
is the top one - "a manager reads this")."""
from __future__ import annotations

from pydantic import BaseModel, Field

from culprit.models.cluster import Cluster
from culprit.models.evidence import PatchOutcome
from culprit.models.patch_run import PatchRun
from culprit.models.rca import RCAResult
from culprit.models.taxonomy import CauseFamily


class ClusterReportEntry(BaseModel):
    cluster: Cluster
    result: RCAResult
    recurrence_badge: str | None = None
    consecutive_cycles: int = 1


class MachineRow(BaseModel):
    """One row in the fleet report's per-machine table - assembled fresh
    per request by joining a cluster's stored members against this run's
    MachineOutcomeRecord rows (see db/repository.py::_load_fleet_report_core),
    the same join get_machine_detail already does for the single-machine
    drill-down, just batched once per run instead of once per machine.
    Not persisted itself - there's nothing here that isn't already stored
    on Cluster/ClusterMember/RCAResult/MachineOutcomeRecord; this is a
    view assembled for the table, not a new fact."""

    vm_id: str
    vm_name: str
    cluster_id: str
    cause_family: CauseFamily
    title: str
    confidence: float
    is_actionable: bool
    has_immediate_fix: bool
    outcome: PatchOutcome | None = Field(
        default=None,
        description="None for a run that predates per-machine outcome tracking - not an error.",
    )
    has_extension_finding: bool = Field(
        default=False,
        description="True when this machine's guest patch extension reported an error/warning "
        "status of its own (collectors/patch_extension_status.py) - surfaced as a per-cluster "
        "count on the Fleet Report, same altitude the Missing Evidence rollup already lives at.",
    )


class FleetTrend(BaseModel):
    """Cycle-over-cycle movement against the most recent prior *completed*
    run for the same scope_name (proposal Section 8: "trend against
    previous cycles" / Section 14: "compliance % ... rising, and rising
    because the tail is closing"). A negative failed_delta or a positive
    compliance_delta_pct is an improvement."""

    previous_run_id: str
    previous_total_failed: int
    previous_compliance_pct: float
    previous_repeat_offender_count: int
    failed_delta: int
    compliance_delta_pct: float


class FleetReport(BaseModel):
    run: PatchRun
    total_machines: int
    total_failed: int
    total_clusters: int
    entries: list[ClusterReportEntry] = Field(default_factory=list, description="Sorted largest cluster first")
    machine_rows: list[MachineRow] = Field(
        default_factory=list,
        description="Flat per-machine view for the fleet report's table - same machines as "
        "`entries[*].cluster.members`, in the same largest-cluster-first order.",
    )
    unresolved_count: int = 0
    repeat_offender_count: int = 0
    trend: FleetTrend | None = Field(
        default=None,
        description="None when there's no prior completed run for this scope_name to compare "
        "against yet (e.g. the very first cycle), not an error.",
    )

    @property
    def compliance_pct(self) -> float:
        if self.total_machines == 0:
            return 100.0
        return round(100.0 * (self.total_machines - self.total_failed) / self.total_machines, 1)
