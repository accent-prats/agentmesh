"""The pre-flight prediction mode (proposal Section 10): "for every
in-scope machine, build a lightweight EvidenceBundle from *current* state
... and check it against the same deterministic rules used post-hoc" -
flagging a machine that would fail the next window while there's still
time to fix it, at essentially zero marginal cost (no model call, only
the rule engine)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from culprit.models.evidence import MachineIdentity
from culprit.models.rca import RCAResult


class PreflightFinding(BaseModel):
    machine: MachineIdentity
    result: RCAResult
    scanned_at: datetime
