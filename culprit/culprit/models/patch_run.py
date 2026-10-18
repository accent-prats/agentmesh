"""Patch run domain models - the unit of work a maintenance cycle produces."""
from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field

from culprit.models.evidence import EvidenceBundle


class TriggerMode(str, enum.Enum):
    SCHEDULED = "scheduled"
    EVENT_DRIVEN = "event_driven"
    AD_HOC = "ad_hoc"
    PRE_FLIGHT = "pre_flight"


class RunStatus(str, enum.Enum):
    COLLECTING = "collecting"
    NORMALIZING = "normalizing"
    CLUSTERING = "clustering"
    DIAGNOSING = "diagnosing"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


class PatchRun(BaseModel):
    """One Azure Update Manager maintenance run, as Culprit sees it."""

    run_id: str
    maintenance_configuration_id: str
    subscription_id: str
    scope_name: str = Field(..., description="e.g. 'prod-linux-weekly', the maintenance config's friendly name")
    started_at: datetime
    ended_at: datetime | None = None
    total_machines: int
    trigger_mode: TriggerMode = TriggerMode.SCHEDULED
    status: RunStatus = RunStatus.COLLECTING

    def failed_count(self, bundles: list[EvidenceBundle]) -> int:
        return sum(1 for b in bundles if b.outcome.status.lower() not in ("succeeded", "completedwithwarnings"))


class RunSummary(BaseModel):
    """One row of the Runs list page - "which update jobs is Culprit
    monitoring" (proposal Section 8's third altitude starts from here):
    every `PatchRun` Culprit has ever diagnosed, most recent first."""

    run_id: str
    scope_name: str
    maintenance_configuration_id: str
    trigger_mode: str
    stage: str
    started_at: datetime
    ended_at: datetime | None = None
    # When this run was actually triggered, as opposed to `started_at`
    # (the evidence-collection window's start, which a large "Hours back"
    # value can push days into the past). None only for rows a database
    # wrote before this column existed. See repository._RUN_RECENCY.
    created_at: datetime | None = None
    total_machines: int
    failed_machines: int
    total_clusters: int
