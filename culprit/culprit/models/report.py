"""The fleet-level report model (proposal Section 8: three artefacts, this
is the top one - "a manager reads this")."""
from __future__ import annotations

from pydantic import BaseModel, Field

from culprit.models.cluster import Cluster
from culprit.models.patch_run import PatchRun
from culprit.models.rca import RCAResult


class ClusterReportEntry(BaseModel):
    cluster: Cluster
    result: RCAResult
    recurrence_badge: str | None = None
    consecutive_cycles: int = 1


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
