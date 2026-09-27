"""A scripted stand-in for DeepRCAAgent, used by the demo/tests when no
Anthropic credentials are configured.

This is clearly a fallback, not a substitute: `run_demo.py` logs loudly
which mode it's running in, and this class implements the exact same
`diagnose()` interface as the real agent (culprit/pipeline/rca_agent.py),
so swapping one for the other is the only difference between an offline
demo run and a real Claude-reasoned run. It exists so the event demo and
the test suite work with zero API key, not to imitate model reasoning
generally.
"""
from __future__ import annotations

from culprit.models.cluster import Cluster
from culprit.models.evidence import EvidenceBundle
from culprit.models.rca import (
    CausalStep,
    RCAResult,
    RemediationPlaybook,
    RemediationStep,
    ResultOrigin,
    RiskLevel,
    RuledOutCause,
)
from culprit.models.taxonomy import CauseFamily


class ScriptedRCAAgent:
    """Recognizes the two demo clusters that reach deep RCA (window
    exhaustion, and the deliberately sparse "unresolved" case) by their
    normalized error code, and falls back to a generic low-confidence
    result for anything else it doesn't recognize - it is not a general
    reasoning engine."""

    def diagnose(
        self,
        cluster: Cluster,
        representative: EvidenceBundle,
        near_misses: list[str] | None = None,
        retrieval_context: str = "",
    ) -> RCAResult:
        error = (representative.outcome.error_code or "").lower()
        if error == "maintenancewindowexceeded":
            return self._window_exhaustion(cluster, representative)
        return self._unresolved(cluster, representative)

    def _window_exhaustion(self, cluster: Cluster, representative: EvidenceBundle) -> RCAResult:
        assessment_ev = next((e for e in representative.timeline if "pending updates" in e.summary), None)
        result_ev = next((e for e in representative.timeline if e.kind == "patch_result" and "MaintenanceWindowExceeded" in e.summary), None)
        refs_backlog = [assessment_ev.raw_ref] if assessment_ev else [representative.timeline[0].raw_ref]
        refs_result = [result_ev.raw_ref] if result_ev else [representative.timeline[-1].raw_ref]

        return RCAResult(
            cluster_id=cluster.cluster_id,
            origin=ResultOrigin.DEEP_RCA,
            cause_family=CauseFamily.WINDOW_SCHEDULING,
            title="Maintenance window too short for the accumulated patch backlog",
            causal_chain=[
                CausalStep(order=1, statement="This machine had not completed a patch cycle in roughly 5 months, leaving a large backlog of pending updates", evidence_refs=refs_backlog),
                CausalStep(order=2, statement="The scheduled 180-minute window was long enough to install 30 of 45 pending packages before being cut off", evidence_refs=refs_result),
                CausalStep(order=3, statement="Azure Update Manager reported MaintenanceWindowExceeded - a timeout, not a package-level error", evidence_refs=refs_result),
            ],
            ruled_out=[
                RuledOutCause(candidate="Disk exhaustion", reason="No low-disk precondition present in the evidence for this machine"),
                RuledOutCause(candidate="Agent unavailability", reason="No heartbeat gap observed during the window"),
            ],
            confidence=0.72,
            missing_evidence=[
                "Per-package install duration to confirm the backlog theory rather than a single slow package"
            ],
            remediation=RemediationPlaybook(
                immediate_fix=[
                    RemediationStep(order=1, instruction="Run a one-off extended-window patch job for this machine (e.g. 6 hours) to clear the backlog", expected_result="All pending packages install"),
                    RemediationStep(order=2, instruction="Re-run assessment", expected_result="Machine reports compliant with the normal schedule going forward"),
                ],
                immediate_risk=RiskLevel.LOW,
                immediate_scope="per_machine",
                preventive_fix="Investigate why this machine's schedule lapsed for ~5 months (excluded tag, deallocated most of the time, schedule drift) and correct it so backlogs of this size don't recur.",
                preventive_risk=RiskLevel.MEDIUM,
                phase2_candidate=False,
                phase2_rationale="Extending a maintenance window is a scheduling change worth a human's judgment the first time it's seen for a given machine class.",
            ),
        )

    def _unresolved(self, cluster: Cluster, representative: EvidenceBundle) -> RCAResult:
        return RCAResult(
            cluster_id=cluster.cluster_id,
            origin=ResultOrigin.DEEP_RCA,
            cause_family=CauseFamily.UNRESOLVED,
            title="Insufficient evidence for a confident root cause",
            causal_chain=[],
            ruled_out=[],
            confidence=0.15,
            missing_evidence=list(representative.collection_gaps) or [
                "Guest-side Windows Update / CBS log content - Run Command did not return"
            ],
            remediation=RemediationPlaybook(
                immediate_fix=[
                    RemediationStep(order=1, instruction="Manually verify WinRM/guest agent connectivity, then re-run collection", expected_result="Guest logs become available for a confident diagnosis"),
                ],
                immediate_risk=RiskLevel.LOW,
                phase2_candidate=False,
                phase2_rationale="Not diagnosed - never eligible for automation.",
            ),
        )
