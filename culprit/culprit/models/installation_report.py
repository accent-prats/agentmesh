"""The Patch Installation Report - a full-fleet, Azure Update Manager-
style view per run (every machine's outcome: Succeeded/Failed/
Unresponsive or Shutdown/Excluded), distinct from the Fleet Report's own
cause-clustering/RCA view, which stays scoped to failures only.

"Unresponsive or Shutdown" is Culprit's own label for Azure Update
Manager's native `Unknown` patch-result status (a VM that never posted a
result in the window) - a best-effort interpretation of the legacy report
this mirrors, not a verified mapping against a real tenant.

"Excluded" is computed as (subscription total) - (every VM that reported
any status) - a count only. Culprit does not resolve *which* specific
VMs that is (see api/routes_runs.py/pipeline/live_run.py for where this
is computed) - a deliberate, simpler choice over cross-referencing
Microsoft.Maintenance/configurationAssignments, which has no prior art
anywhere in this codebase and couldn't be validated against a real tenant.
"""
from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field, computed_field

from culprit.models.patch_run import PatchRun
from culprit.models.taxonomy import CauseFamily


class InstallationStatus(str, enum.Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNRESPONSIVE_OR_SHUTDOWN = "unresponsive_or_shutdown"
    EXCLUDED = "excluded"


class InstallationOutcomeRow(BaseModel):
    vm_id: str
    vm_name: str
    status: InstallationStatus
    subscription_id: str
    resource_group: str
    started_at: datetime | None = None
    ended_at: datetime | None = None

    # Failure-only fields - all None for Succeeded/Unresponsive rows.
    error_code: str | None = None
    error_message: str | None = None
    # The well-known Azure Update Manager guest-log convention for this
    # machine's OS family (e.g. .../Microsoft.CPlat.Core.LinuxPatchExtension/
    # .../core.log for Linux) - stated as a plain convention, not a path
    # Culprit has independently collected or verified exists on the guest,
    # consistent with this app's own "no citation, no claim" discipline
    # for anything it asserts more strongly.
    log_path: str | None = None

    # Culprit's own RCA, joined in only when this machine was also
    # clustered and diagnosed (a FAILED row that never made it into a
    # cluster - e.g. capped out by _MAX_MACHINES_PER_RUN - simply has
    # none of these, same "absence isn't an error" shape as MachineRow's
    # own nullable outcome).
    cause_family: CauseFamily | None = None
    rca_title: str | None = None
    rca_confidence: float | None = None
    cluster_id: str | None = None


class InstallationReport(BaseModel):
    run: PatchRun
    rows: list[InstallationOutcomeRow] = Field(default_factory=list)
    # Not derived from len(rows) - Excluded has no per-VM rows under this
    # report's chosen derivation (see module docstring), so the count has
    # to be carried separately rather than computed by filtering rows.
    excluded_count: int = 0

    # @computed_field (not a bare @property) - found in review: a plain
    # @property is invisible to Pydantic's own serialization (model_dump/
    # the JSON this model's own API route returns via response_model=
    # InstallationReport), so every one of these silently never reached
    # GET /runs/{run_id}/installation-report's actual response body - a
    # gap the existing tests missed because they computed these counts by
    # hand from `rows` instead of reading the field the real endpoint
    # returns.
    @computed_field
    @property
    def succeeded_count(self) -> int:
        return sum(1 for r in self.rows if r.status == InstallationStatus.SUCCEEDED)

    @computed_field
    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.rows if r.status == InstallationStatus.FAILED)

    @computed_field
    @property
    def unresponsive_count(self) -> int:
        return sum(1 for r in self.rows if r.status == InstallationStatus.UNRESPONSIVE_OR_SHUTDOWN)

    @computed_field
    @property
    def total_count(self) -> int:
        return len(self.rows) + self.excluded_count
