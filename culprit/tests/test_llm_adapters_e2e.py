"""Proves an OpenAI-compatible provider (shared/src/llm/) can stand in
for Anthropic inside DeepRCAAgent without DeepRCAAgent itself changing at
all - the point of the shared adapter package existing. Adapter-internal
request/response-shape coverage lives in
shared/tests/test_llm_adapters.py; this is the one integration point that
also needs Culprit's own pipeline/models, so it stays here instead."""
from __future__ import annotations

from datetime import datetime, timezone

from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.pipeline.fingerprint import cluster_run
from culprit.pipeline.rca_agent import DeepRCAAgent
from shared.src.llm.openai_compatible import OpenAICompatibleClient


class FakeHttpResponse:
    def __init__(self, json_data: dict, status_code: int = 200):
        self._json = json_data
        self.status_code = status_code

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._json


def _bundle() -> EvidenceBundle:
    machine = MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )
    outcome = PatchOutcome(status="Failed", error_code="MaintenanceWindowExceeded")
    events = [
        TimelineEvent(
            ts=datetime.now(timezone.utc), source=Source.AZURE_CONTROL_PLANE, kind="patch_result",
            summary="window exceeded", detail={}, raw_ref="ref-1",
        )
    ]
    return EvidenceBundle(run_id="run-1", machine=machine, outcome=outcome, timeline=events, collection_started_at=datetime.now(timezone.utc))


def test_openai_compatible_client_produces_a_valid_rca_result(monkeypatch):
    bundle = _bundle()
    cluster = cluster_run("run-1", [bundle])[0]

    def fake_post(url, *, headers, json, timeout):
        tool_name = json["tools"][0]["function"]["name"]
        arguments = (
            '{"cause_family": "configuration", "title": "t", "causal_chain": '
            '[{"order": 1, "statement": "s", "evidence_refs": ["ref-1"]}], '
            '"ruled_out": [], "confidence": 0.8, "missing_evidence": [], '
            '"immediate_fix_steps": [], "immediate_risk": "low", "immediate_scope": "per_machine", '
            '"preventive_fix": "p", "preventive_risk": "low", "rollback": "", '
            '"phase2_candidate": false, "phase2_rationale": ""}'
        )
        return FakeHttpResponse({"choices": [{"message": {"tool_calls": [{"function": {"name": tool_name, "arguments": arguments}}]}}]})

    monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.post", fake_post)
    client = OpenAICompatibleClient(api_key="sk-x", base_url="https://api.openai.com/v1")
    agent = DeepRCAAgent(client=client, model="gpt-5")

    result = agent.diagnose(cluster, bundle)

    assert result.cause_family.value == "configuration"
    assert result.confidence == 0.8
    assert result.causal_chain[0].evidence_refs == ["ref-1"]
