"""_calibrate_confidence (culprit/pipeline/rca_agent.py) - found 2026-10-19
from a real user complaint: a cluster whose causal chain cited only 2
generic Azure control-plane facts, with hedged wording ("suggesting an
underlying issue... or entitlement"), was shown as HIGH CONFIDENCE. The
model's own `confidence` field was never independently checked against how
well-supported the conclusion actually was - this caps it down whenever
either of two deterministic, auditable signals fires: a single cited
evidence source backing the whole causal chain, or hedging language in the
causal chain's own statements."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.models.taxonomy import CauseFamily
from culprit.pipeline.fingerprint import cluster_run
from culprit.pipeline.rca_agent import _TOOL_NAME, DeepRCAAgent, _LOW_CONFIDENCE_CEILING


@dataclass
class FakeBlock:
    type: str
    name: str | None = None
    input: dict | None = None


@dataclass
class FakeResponse:
    content: list[FakeBlock]
    stop_reason: str = "tool_use"


@dataclass
class FakeMessagesAPI:
    next_response: FakeResponse
    last_kwargs: dict = field(default_factory=dict)

    def create(self, **kwargs) -> FakeResponse:
        self.last_kwargs = kwargs
        return self.next_response


class FakeAnthropicClient:
    def __init__(self, response: FakeResponse):
        self.messages = FakeMessagesAPI(next_response=response)


def _machine() -> MachineIdentity:
    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )


def _single_source_bundle() -> EvidenceBundle:
    """The exact real-world shape: two Azure-control-plane-only facts, no
    guest-level corroboration - what the real user-reported RCA actually
    had."""
    events = [
        TimelineEvent(
            ts=datetime.now(timezone.utc), source=Source.AZURE_CONTROL_PLANE, kind="patch_result",
            summary="patchinstallationresults -> Failed", detail={}, raw_ref="ref-install",
        ),
        TimelineEvent(
            ts=datetime.now(timezone.utc), source=Source.AZURE_CONTROL_PLANE, kind="patch_assessment",
            summary="patchassessmentresults -> Succeeded, 130 patch(es) pending", detail={}, raw_ref="ref-assessment",
        ),
    ]
    return EvidenceBundle(
        run_id="run-1", machine=_machine(), outcome=PatchOutcome(status="Failed"),
        timeline=events, collection_started_at=datetime.now(timezone.utc),
    )


def _multi_source_bundle() -> EvidenceBundle:
    events = [
        TimelineEvent(
            ts=datetime.now(timezone.utc), source=Source.AZURE_CONTROL_PLANE, kind="patch_result",
            summary="patchinstallationresults -> Failed", detail={}, raw_ref="ref-install",
        ),
        TimelineEvent(
            ts=datetime.now(timezone.utc), source=Source.GUEST_LINUX, kind="disk_usage",
            summary="/boot at 100% used, 0 free", detail={"disk_low": True}, raw_ref="ref-disk",
        ),
    ]
    return EvidenceBundle(
        run_id="run-1", machine=_machine(), outcome=PatchOutcome(status="Failed"),
        timeline=events, collection_started_at=datetime.now(timezone.utc),
    )


def _diagnose(bundle, causal_chain, confidence):
    cluster = cluster_run("run-1", [bundle])[0]
    tool_input = {
        "cause_family": "capacity", "title": "t", "causal_chain": causal_chain,
        "ruled_out": [], "confidence": confidence, "missing_evidence": [],
        "immediate_fix_steps": [], "immediate_risk": "low", "immediate_scope": "per_machine",
        "preventive_fix": "p", "preventive_risk": "low", "rollback": "",
        "phase2_candidate": False, "phase2_rationale": "",
    }
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=tool_input)])
    agent = DeepRCAAgent(client=FakeAnthropicClient(response))
    return agent.diagnose(cluster, bundle)


def test_high_confidence_is_capped_when_only_one_source_backs_the_chain():
    bundle = _single_source_bundle()
    causal_chain = [
        {"order": 1, "statement": "The patch installation failed due to insufficient disk space.", "evidence_refs": ["ref-install"]},
        {"order": 2, "statement": "130 patches are still pending.", "evidence_refs": ["ref-assessment"]},
    ]
    result = _diagnose(bundle, causal_chain, confidence=0.9)
    assert result.confidence == _LOW_CONFIDENCE_CEILING


def test_high_confidence_is_not_capped_with_genuine_multi_source_corroboration():
    """The positive case: two DIFFERENT sources (control-plane + guest-level
    disk reading) genuinely corroborate each other and the wording is a
    plain factual statement - this must NOT be capped."""
    bundle = _multi_source_bundle()
    causal_chain = [
        {"order": 1, "statement": "The patch installation failed due to insufficient disk space.", "evidence_refs": ["ref-install"]},
        {"order": 2, "statement": "The /boot partition had 0 bytes free at scan time.", "evidence_refs": ["ref-disk"]},
    ]
    result = _diagnose(bundle, causal_chain, confidence=0.9)
    assert result.confidence == 0.9


def test_high_confidence_is_capped_when_the_wording_hedges_even_with_multiple_sources():
    """Hedging language is its own independent trigger - good source
    diversity doesn't excuse a causal chain that admits it's guessing."""
    bundle = _multi_source_bundle()
    causal_chain = [
        {
            "order": 1,
            "statement": "The patch installation failed, suggesting an underlying issue with the system state or entitlement.",
            "evidence_refs": ["ref-install", "ref-disk"],
        },
    ]
    result = _diagnose(bundle, causal_chain, confidence=0.9)
    assert result.confidence == _LOW_CONFIDENCE_CEILING


def test_already_low_confidence_is_never_raised():
    """Calibration only ever lowers confidence - a model that already
    reported low confidence for a single-source result must not have its
    number bumped up to the ceiling."""
    bundle = _single_source_bundle()
    causal_chain = [{"order": 1, "statement": "Failed due to disk space.", "evidence_refs": ["ref-install"]}]
    result = _diagnose(bundle, causal_chain, confidence=0.3)
    assert result.confidence == 0.3


def test_confidence_exactly_at_the_ceiling_is_unchanged():
    bundle = _single_source_bundle()
    causal_chain = [{"order": 1, "statement": "Failed due to disk space.", "evidence_refs": ["ref-install"]}]
    result = _diagnose(bundle, causal_chain, confidence=_LOW_CONFIDENCE_CEILING)
    assert result.confidence == _LOW_CONFIDENCE_CEILING


def test_calibration_logs_why_it_fired(caplog):
    bundle = _single_source_bundle()
    causal_chain = [{"order": 1, "statement": "Failed due to disk space.", "evidence_refs": ["ref-install"]}]
    with caplog.at_level("INFO"):
        _diagnose(bundle, causal_chain, confidence=0.9)
    assert any("RCA confidence capped" in r.message and "0.90" in r.message for r in caplog.records)
