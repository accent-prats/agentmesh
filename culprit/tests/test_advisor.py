from __future__ import annotations

from culprit.models.rca import CausalStep, RCAResult, RemediationPlaybook, ResultOrigin, RiskLevel
from culprit.models.taxonomy import CauseFamily
from culprit.pipeline.advisor import advise, compute_recurrence, enforce_automation_safety


def _result(risk: RiskLevel, phase2: bool) -> RCAResult:
    return RCAResult(
        cluster_id="c1",
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.CAPACITY,
        title="t",
        causal_chain=[CausalStep(order=1, statement="s", evidence_refs=["r"])],
        confidence=0.9,
        remediation=RemediationPlaybook(immediate_risk=risk, phase2_candidate=phase2),
    )


def test_high_risk_phase2_candidate_is_overridden():
    result = _result(RiskLevel.HIGH, True)
    fixed = enforce_automation_safety(result)
    assert fixed.remediation.phase2_candidate is False
    assert "Overridden" in fixed.remediation.phase2_rationale


def test_low_risk_phase2_candidate_is_left_alone():
    result = _result(RiskLevel.LOW, True)
    fixed = enforce_automation_safety(result)
    assert fixed.remediation.phase2_candidate is True


def test_recurrence_first_time_seen():
    info = compute_recurrence("key-a", [])
    assert info.consecutive_cycles == 1
    assert info.is_repeat_offender is False
    assert info.badge is None


def test_recurrence_streak_counts_consecutive_prior_runs():
    history = [["key-a", "key-b"], ["key-a"], ["key-c"]]
    info = compute_recurrence("key-a", history)
    assert info.consecutive_cycles == 3
    assert info.is_repeat_offender is True
    assert info.badge == "3rd cycle recurring"


def test_recurrence_streak_stops_at_first_gap():
    history = [["key-a"], ["key-z"], ["key-a"]]  # missing in the 2nd most recent run
    info = compute_recurrence("key-a", history)
    assert info.consecutive_cycles == 2


def test_advise_returns_both_result_and_recurrence():
    result = _result(RiskLevel.LOW, True)
    fixed, recurrence = advise(result, "key-a", [["key-a"]])
    assert fixed.remediation.phase2_candidate is True
    assert recurrence.consecutive_cycles == 2
