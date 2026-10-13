"""Phase 2 remediation execution models - the request/response/audit
shapes for api/routes_remediation.py. See culprit/remediation/ for the
actual Azure-facing execution, and RemediationPlaybook.phase2_candidate/
automation_params (culprit/models/rca.py) for how a diagnosis opts in.
"""
from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from culprit.models.taxonomy import CauseFamily


class RemediationActionType(str, enum.Enum):
    DISK_CLEANUP = "disk_cleanup"


# The entire set of (cause family -> action) pairings this app knows how
# to execute. phase2_candidate=True alone is NOT sufficient to execute - a
# cause family also needs a wired entry here, so every other
# phase2_candidate diagnosis still surfaces a human playbook only, pending
# its own reviewed action. Lives here (not in api/routes_remediation.py,
# where it's actually enforced) so reporting/render.py can also read it
# for the Fleet Report's "Run remediation" button, without a
# reporting -> api import. Extending this is a deliberate code change and
# review, the same bar culprit/remediation/scripts.py's own allow-list is
# held to.
SUPPORTED_ACTIONS: dict[CauseFamily, RemediationActionType] = {
    CauseFamily.CAPACITY: RemediationActionType.DISK_CLEANUP,
}


class RemediationStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"


class RemediationActionRequest(BaseModel):
    action_type: RemediationActionType
    # Required, caller-supplied - there is no auth-derived identity
    # anywhere in this codebase to pull from instead (the shared-token
    # auth path has none; the Portal-JWT path's claims are decoded then
    # discarded by the middleware today). Mirrors the exact existing
    # precedent: SubmitVerdictBody.reviewer in routes_verdicts.py.
    requested_by: str = Field(..., min_length=1)
    vm_ids: list[str] | None = Field(default=None, description="None = every member of the cluster")

    @field_validator("requested_by")
    @classmethod
    def _requested_by_must_not_be_blank(cls, v: str) -> str:
        # min_length=1 alone counts characters, not content - "   " passes
        # it. Found in review: a caller that skips the browser widget
        # (curl, a script) could otherwise execute a real remediation with
        # no identifiable human attached, directly undermining the "a
        # human confirms, every time" guarantee this whole feature is
        # built around.
        stripped = v.strip()
        if not stripped:
            raise ValueError("requested_by must not be blank")
        return stripped


class RemediationMachineResult(BaseModel):
    vm_id: str
    vm_name: str
    status: RemediationStatus
    message: str
    free_bytes_after: int | None = None


class RemediationExecutionResponse(BaseModel):
    """Always returned with HTTP 200, even on partial failure - a 3-of-5
    machines succeeding is a real, granular outcome to report, not a
    transport error. Matches this codebase's existing style of reporting
    partial outcomes inside a 200 payload (collection_gaps,
    MachineOutcomeRecord.error_*) rather than inventing a status code with
    no other precedent here."""

    run_id: str
    cluster_id: str
    action_type: RemediationActionType
    requested_by: str
    executed_at: datetime
    results: list[RemediationMachineResult] = Field(default_factory=list)
    succeeded_count: int = 0
    failed_count: int = 0


class RemediationLogEntry(BaseModel):
    """One audit-log row (the Remediation log page) - the read-model for
    a persisted RemediationActionRecord (db/models.py)."""

    id: int
    run_id: str
    cluster_id: str
    vm_id: str
    vm_name: str
    cause_family: CauseFamily
    action_type: RemediationActionType
    requested_by: str
    requested_at: datetime
    status: RemediationStatus
    message: str
