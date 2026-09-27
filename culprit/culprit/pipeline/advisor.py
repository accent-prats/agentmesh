"""The remediation advisor step (proposal Section 4, "Advisor" box).

Both the rule engine and the deep RCA agent already produce a
RemediationPlaybook directly as part of their output - a separate LLM call
to turn "cause" into "playbook" would just re-read the same context for no
real gain. What this module does instead is the two things that have to
happen *after* either of those, regardless of which one produced the
result:

  1. Safety-net the risk/automation flags. A model (or a rule author) can
     mark something phase2_candidate=True while also marking it high-risk
     - that combination is exactly what Section 11's promotion gate exists
     to prevent, so it's enforced here structurally rather than trusted.
  2. Detect recurrence across cycles. A cluster's `cluster_key` (from the
     Fingerprint, stable across runs) is what lets Culprit say "this is the
     third cycle running" - which reframes a finding from "a patch failed"
     to "a policy is missing" per the worked example in Section 8.
"""
from __future__ import annotations

from dataclasses import dataclass

from culprit.models.rca import RCAResult, RiskLevel


@dataclass
class RecurrenceInfo:
    cluster_key: str
    consecutive_cycles: int  # 1 = first time seen, 2 = seen last cycle too, etc.
    is_repeat_offender: bool  # True once consecutive_cycles >= REPEAT_THRESHOLD

    @property
    def badge(self) -> str | None:
        if not self.is_repeat_offender:
            return None
        return f"{self.consecutive_cycles}{_ordinal_suffix(self.consecutive_cycles)} cycle recurring"


REPEAT_THRESHOLD = 2


def _ordinal_suffix(n: int) -> str:
    if 10 <= n % 100 <= 20:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


def enforce_automation_safety(result: RCAResult) -> RCAResult:
    """Never trust a high-risk immediate fix marked as a Phase 2 automation
    candidate - override it defensively rather than propagate a model or
    rule-authoring mistake into the promotion pipeline."""
    if result.remediation and result.remediation.immediate_risk == RiskLevel.HIGH and result.remediation.phase2_candidate:
        result.remediation.phase2_candidate = False
        result.remediation.phase2_rationale = (
            "Overridden: immediate fix is high-risk, which Section 11 excludes from automation "
            "regardless of confidence."
        ) + ((" Original rationale: " + result.remediation.phase2_rationale) if result.remediation.phase2_rationale else "")
    return result


def compute_recurrence(cluster_key: str, historical_cluster_keys_by_run: list[list[str]]) -> RecurrenceInfo:
    """`historical_cluster_keys_by_run` is the list of cluster_key sets seen
    in previous runs, ordered most-recent-first. Consecutive presence
    (not total occurrence count) is what matters - a cause that vanished
    for two cycles and came back is a new incident, not a running streak.
    """
    streak = 1
    for run_keys in historical_cluster_keys_by_run:
        if cluster_key in run_keys:
            streak += 1
        else:
            break
    return RecurrenceInfo(
        cluster_key=cluster_key,
        consecutive_cycles=streak,
        is_repeat_offender=streak >= REPEAT_THRESHOLD,
    )


def advise(result: RCAResult, cluster_key: str, historical_cluster_keys_by_run: list[list[str]]) -> tuple[RCAResult, RecurrenceInfo]:
    result = enforce_automation_safety(result)
    recurrence = compute_recurrence(cluster_key, historical_cluster_keys_by_run)
    return result, recurrence
