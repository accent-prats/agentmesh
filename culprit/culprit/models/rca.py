"""RCA output models.

These are the schema the deep RCA agent (culprit/pipeline/rca_agent.py) is
constrained to produce via strict tool-use, and the schema the rule engine
(culprit/pipeline/rules.py) produces directly without a model in the loop.
Both paths converge on `RCAResult`, so everything downstream (advisor,
reporting, precision tracking) is agnostic to which one produced a given
result.

The hard constraint from the proposal ("no citation, no claim") is encoded
structurally: `CausalStep.evidence_refs` is a required, non-empty list of
`raw_ref` pointers into the originating EvidenceBundle's timeline. A result
with an empty `evidence_refs` on any step fails validation.
"""
from __future__ import annotations

import enum

from pydantic import BaseModel, Field, field_validator, model_validator

from culprit.models.taxonomy import CauseFamily


class ResultOrigin(str, enum.Enum):
    RULE_ENGINE = "rule_engine"
    DEEP_RCA = "deep_rca"


class CausalStep(BaseModel):
    """One link in the causal chain, e.g. 'Unattended-upgrades retains
    every installed kernel; no autoremove policy is applied to this image'.
    Ordered - step 1 is the deepest cause, the last step is the symptom
    Azure actually reported.
    """

    order: int
    statement: str
    evidence_refs: list[str] = Field(
        ..., min_length=1, description="raw_ref pointers this statement is derived from"
    )

    @field_validator("evidence_refs")
    @classmethod
    def _no_blank_refs(cls, v: list[str]) -> list[str]:
        if any(not ref.strip() for ref in v):
            raise ValueError("evidence_refs entries must not be blank")
        return v


class RuledOutCause(BaseModel):
    candidate: str
    reason: str
    evidence_refs: list[str] = Field(default_factory=list)


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RemediationStep(BaseModel):
    order: int
    instruction: str
    expected_result: str = ""


class RemediationPlaybook(BaseModel):
    """Both halves the proposal insists on keeping separate: the fix-now
    and the stop-it-recurring. Conflating them is exactly what lets a cause
    come back next cycle while everyone believes it was 'fixed'."""

    immediate_fix: list[RemediationStep] = Field(default_factory=list)
    immediate_risk: RiskLevel = RiskLevel.LOW
    immediate_scope: str = Field(default="per_machine", description="'per_machine' or 'fleet_wide'")
    preventive_fix: str = ""
    preventive_risk: RiskLevel = RiskLevel.MEDIUM
    rollback: str = ""
    phase2_candidate: bool = False
    phase2_rationale: str = ""


class RCAResult(BaseModel):
    """The full diagnosis for one Cluster."""

    cluster_id: str
    origin: ResultOrigin
    cause_family: CauseFamily
    title: str
    causal_chain: list[CausalStep] = Field(default_factory=list)
    ruled_out: list[RuledOutCause] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="What the agent still needs to raise confidence - a non-empty list here "
        "is a request to re-dispatch the collector, not a shrug.",
    )
    remediation: RemediationPlaybook | None = None

    @model_validator(mode="after")
    def _chain_must_cite_when_confident(self) -> "RCAResult":
        # A confident result with zero causal steps is exactly the "confident
        # nothing" failure mode the proposal calls out - block it structurally.
        # A model-level (not field-level) validator on purpose: field order
        # in Pydantic v2 controls what `info.data` has already been
        # validated, which makes a field_validator on `causal_chain` see
        # `confidence` only if confidence happens to be declared earlier -
        # fragile to reorder. Checking both fields together here is robust
        # regardless of declaration order.
        if self.confidence >= 0.5 and not self.causal_chain:
            raise ValueError("causal_chain must be non-empty when confidence >= 0.5")
        return self

    @property
    def is_actionable(self) -> bool:
        """A result is actionable if it's confident enough to hand to an
        engineer without a caveat banner - the display/notification layer
        uses this, not a raw confidence threshold, so the bar lives in one
        place."""
        return self.confidence >= 0.6 and not self.missing_evidence
