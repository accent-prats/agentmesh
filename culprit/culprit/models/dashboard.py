"""The Console page's dashboard data - a different altitude from
FleetReport (one run's own detail): this crosses *several* runs (a
compliance trend) and aggregates *within* one run without reconstructing
every RCAResult (top causes). See db/repository.py's dashboard-building
functions for how each piece is actually assembled - all read-only,
nothing here is persisted independently of what Cluster/RunRecord/
RCAResultRecord already store."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from culprit.models.report import FleetReport
from culprit.models.taxonomy import CauseFamily


class ComplianceTrendPoint(BaseModel):
    """One completed run's compliance %, for the Console dashboard's
    trend line - oldest first (left-to-right charting order), scoped to
    a single scope_name the same way FleetTrend already is (a different
    maintenance job's history isn't a fair comparison point).
    `failed_machines` rides along for free (same query, same row) so the
    dashboard's own tile-arrow deltas can be read off the last two points
    here instead of needing a separate, expensive FleetTrend/compute_trend
    call - see db/repository.py::build_dashboard_summary."""

    run_id: str
    started_at: datetime
    failed_machines: int
    compliance_pct: float


class CauseBreakdownEntry(BaseModel):
    """One cause family's share of a run's failures, ranked by machine
    count - the Console dashboard's "what's actually breaking things"
    list. `cause_family` is RCAResultRecord's own indexed column; no
    RCAResult.model_validate (title/remediation/evidence) is needed to
    build this."""

    cause_family: CauseFamily
    machines: int


class DashboardSummary(BaseModel):
    """Everything the Console page's dashboard shows. `latest_run` is
    None only when there isn't yet a single completed run anywhere -
    the dashboard then falls back to a plain onboarding prompt instead
    of empty/zero-filled tiles. `compliance_trend` has fewer than 2
    points whenever there's nothing to meaningfully chart yet (first
    cycle, or latest_run itself is None) - not an error, same shape as
    FleetTrend's own None-means-no-prior-cycle convention.

    `latest_run.trend` is deliberately always None here - unlike the
    fleet report page's own copy of the same run, this dashboard never
    displays `previous_repeat_offender_count` (the one FleetTrend field
    with no cheap, column-only equivalent), so computing a full
    FleetTrend here would mean reconstructing the previous run's
    clusters/RCAResults purely to throw that one field away. Use
    `failed_delta`/`compliance_delta_pct` below instead - the same two
    numbers the fleet report page's tile arrows show, derived from
    `compliance_trend`'s own last two points (already fetched, zero
    extra cost) rather than a second, expensive reconstruction."""

    latest_run: FleetReport | None = None
    compliance_trend: list[ComplianceTrendPoint] = Field(default_factory=list)
    top_causes: list[CauseBreakdownEntry] = Field(default_factory=list)
    failed_delta: int | None = None
    compliance_delta_pct: float | None = None
