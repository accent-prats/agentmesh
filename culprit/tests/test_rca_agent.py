from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.models.taxonomy import CauseFamily
from culprit.pipeline.fingerprint import cluster_run
from culprit.pipeline.rca_agent import _RCA_TOOL_SCHEMA, DeepRCAAgent, _TOOL_NAME


@dataclass
class FakeBlock:
    type: str
    name: str | None = None
    input: dict | None = None
    text: str | None = None


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


def _cluster(bundle):
    return cluster_run("run-1", [bundle])[0]


_VALID_INPUT: dict[str, Any] = {
    "cause_family": "window_scheduling",
    "title": "Backlog too large for the window",
    "causal_chain": [{"order": 1, "statement": "Backlog accumulated over months", "evidence_refs": ["ref-1"]}],
    "ruled_out": [],
    "confidence": 0.7,
    "missing_evidence": [],
    "immediate_fix_steps": [{"order": 1, "instruction": "Run an extended window", "expected_result": "compliant"}],
    "immediate_risk": "low",
    "immediate_scope": "per_machine",
    "preventive_fix": "Investigate schedule drift",
    "preventive_risk": "medium",
    "rollback": "",
    "phase2_candidate": False,
    "phase2_rationale": "",
}


def test_valid_tool_call_parses_into_rca_result():
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=dict(_VALID_INPUT))])
    agent = DeepRCAAgent(client=FakeAnthropicClient(response))
    bundle = _bundle()
    result = agent.diagnose(_cluster(bundle), bundle)
    assert result.cause_family == CauseFamily.WINDOW_SCHEDULING
    assert result.confidence == 0.7
    assert result.causal_chain[0].evidence_refs == ["ref-1"]


def test_diagnose_logs_start_and_completion_with_cluster_and_machine_context(caplog):
    """Found 2026-10-16, tracing a real production timeout: this call had
    no logging of its own - once confirmed (via a raised exception's own
    traceback) that this was the thing actually hanging, there was still
    no way to tell which cluster/machine a given slow call belonged to."""
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=dict(_VALID_INPUT))])
    agent = DeepRCAAgent(client=FakeAnthropicClient(response))
    bundle = _bundle()
    cluster = _cluster(bundle)

    with caplog.at_level("INFO"):
        agent.diagnose(cluster, bundle)

    messages = [r.message for r in caplog.records]
    assert any("RCA diagnose starting" in m and cluster.cluster_id in m and "vm-1" in m for m in messages)
    assert any("RCA diagnose call returned" in m and cluster.cluster_id in m for m in messages)


def test_diagnose_logs_a_warning_on_failure_but_still_raises_the_real_exception(caplog):
    """The most important property of this instrumentation: it must be
    purely observational. A try/except that logs and re-raises can
    accidentally swallow or replace the original exception - this pins
    that the exact same exception type/instance keeps propagating."""
    class ExplodingMessagesAPI:
        def create(self, **kwargs):
            raise TimeoutError("the gateway never responded")

    class ExplodingClient:
        messages = ExplodingMessagesAPI()

    agent = DeepRCAAgent(client=ExplodingClient())
    bundle = _bundle()
    cluster = _cluster(bundle)

    with caplog.at_level("WARNING"):
        try:
            agent.diagnose(cluster, bundle)
            raised = None
        except TimeoutError as exc:
            raised = exc

    assert raised is not None and str(raised) == "the gateway never responded"
    assert any(
        r.levelname == "WARNING" and "RCA diagnose call failed" in r.message and cluster.cluster_id in r.message
        for r in caplog.records
    )


def test_missing_tool_call_downgrades_to_unresolved():
    response = FakeResponse(content=[FakeBlock(type="text", text="I'm not sure.")])
    agent = DeepRCAAgent(client=FakeAnthropicClient(response))
    bundle = _bundle()
    result = agent.diagnose(_cluster(bundle), bundle)
    assert result.cause_family == CauseFamily.UNRESOLVED
    assert result.confidence == 0.0
    assert result.missing_evidence


def test_confident_result_with_empty_causal_chain_is_rejected_and_downgraded():
    """The hard constraint: a confident answer MUST cite evidence. If the
    model (hypothetically) returns confidence >= 0.5 with no causal steps,
    Pydantic validation must reject it and the agent must not propagate a
    'confident nothing' result."""
    bad_input = dict(_VALID_INPUT)
    bad_input["causal_chain"] = []
    bad_input["confidence"] = 0.8
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=bad_input)])
    agent = DeepRCAAgent(client=FakeAnthropicClient(response))
    bundle = _bundle()
    result = agent.diagnose(_cluster(bundle), bundle)
    assert result.cause_family == CauseFamily.UNRESOLVED
    assert "validation" in result.missing_evidence[0].lower()


def test_blank_evidence_ref_is_rejected():
    bad_input = dict(_VALID_INPUT)
    bad_input["causal_chain"] = [{"order": 1, "statement": "x", "evidence_refs": ["   "]}]
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=bad_input)])
    agent = DeepRCAAgent(client=FakeAnthropicClient(response))
    bundle = _bundle()
    result = agent.diagnose(_cluster(bundle), bundle)
    assert result.cause_family == CauseFamily.UNRESOLVED


def test_fabricated_evidence_ref_is_rejected_even_though_well_formed():
    """Found in review 2026-09-27: the non-empty check on evidence_refs
    passes a hallucinated-but-well-formed raw_ref cleanly - 'no citation,
    no claim' was only ever a presence check, not an accuracy check. This
    is the actual cross-reference-against-the-bundle fix."""
    bad_input = dict(_VALID_INPUT)
    bad_input["causal_chain"] = [
        {"order": 1, "statement": "Plausible-sounding but invented", "evidence_refs": ["ref-that-does-not-exist"]}
    ]
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=bad_input)])
    agent = DeepRCAAgent(client=FakeAnthropicClient(response))
    bundle = _bundle()  # only ever produces raw_ref="ref-1"
    result = agent.diagnose(_cluster(bundle), bundle)
    assert result.cause_family == CauseFamily.UNRESOLVED
    assert "ref-that-does-not-exist" in result.missing_evidence[0]


def test_a_mix_of_real_and_fabricated_refs_still_gets_rejected():
    bad_input = dict(_VALID_INPUT)
    bad_input["causal_chain"] = [
        {"order": 1, "statement": "Half real, half invented", "evidence_refs": ["ref-1", "ref-fake"]}
    ]
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=bad_input)])
    agent = DeepRCAAgent(client=FakeAnthropicClient(response))
    bundle = _bundle()
    result = agent.diagnose(_cluster(bundle), bundle)
    assert result.cause_family == CauseFamily.UNRESOLVED


def test_request_includes_model_and_tool_schema():
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=dict(_VALID_INPUT))])
    client = FakeAnthropicClient(response)
    agent = DeepRCAAgent(client=client, model="claude-opus-5")
    bundle = _bundle()
    agent.diagnose(_cluster(bundle), bundle, near_misses=["disk rule abstained"], retrieval_context="some vendor doc")
    kwargs = client.messages.last_kwargs
    assert kwargs["model"] == "claude-opus-5"
    assert kwargs["tools"][0]["name"] == _TOOL_NAME
    assert "disk rule abstained" in kwargs["messages"][0]["content"]
    assert "some vendor doc" in kwargs["messages"][0]["content"]


def test_prompt_surfaces_which_evidence_sources_were_attempted_and_succeeded():
    """sources_attempted/sources_succeeded (pipeline/normalize.py::
    merge_bundle) were already populated faithfully but never read
    anywhere downstream before this - found 2026-10-15 auditing why RCA
    confidence is so often low. Gives the model structured knowledge of
    what evidence universe this deployment even has (e.g. no Datadog
    configured at all) instead of leaving it to infer that from
    collection_gaps prose alone."""
    response = FakeResponse(content=[FakeBlock(type="tool_use", name=_TOOL_NAME, input=dict(_VALID_INPUT))])
    client = FakeAnthropicClient(response)
    agent = DeepRCAAgent(client=client)
    bundle = _bundle().model_copy(update={
        "sources_attempted": [Source.AZURE_CONTROL_PLANE, Source.GUEST_LINUX, Source.AZURE_MONITOR],
        "sources_succeeded": [Source.AZURE_CONTROL_PLANE, Source.AZURE_MONITOR],
    })
    agent.diagnose(_cluster(bundle), bundle, near_misses=[], retrieval_context="")
    prompt = client.messages.last_kwargs["messages"][0]["content"]

    assert "Evidence sources attempted: azure_control_plane, guest_linux, azure_monitor" in prompt
    assert "succeeded: azure_control_plane, azure_monitor" in prompt
    # guest_linux was attempted but is absent from succeeded - the model
    # should be able to see that asymmetry directly in this one line.
    assert "guest_linux" not in prompt.split("succeeded:")[1].split("\n")[0]


def _assert_object_schema_satisfies_strict_mode(schema: Any, path: str = "$") -> None:
    """OpenAI's strict function-calling mode (Culprit's own tool schema has
    `"strict": True`) imposes two independent constraints on every object
    schema, both found the hard way: (1 - found 2026-10-18 from a real
    production 400 Bad Request) `required` must list every key in
    `properties` - "optional" there is expressed by the model supplying an
    empty/default value, not by omitting the key from `required` - both
    `ruled_out`'s and `immediate_fix_steps`'s item schemas had a property
    (`evidence_refs`, `expected_result` respectively) missing from
    `required`, and nothing caught it until a live OpenAI call rejected it
    outright; and (2 - found in review of that same fix, before it ever
    caused a real failure) every object schema must set
    `"additionalProperties": false` - true everywhere in the schema today,
    but the first version of this test only checked constraint 1, so a
    future object added without this would have passed the test and still
    400'd live, defeating the point of having the test at all. Walks the
    whole schema recursively so any future edit that reintroduces either
    violation - anywhere - fails a test instead of a live run."""
    if not isinstance(schema, dict):
        return
    if schema.get("type") == "object" and "properties" in schema:
        properties = set(schema["properties"])
        required = set(schema.get("required", []))
        missing = properties - required
        assert not missing, f"{path}: required is missing {missing} (strict mode needs every property required)"
        assert schema.get("additionalProperties") is False, f"{path}: must set additionalProperties: false for strict mode"
        for key, subschema in schema["properties"].items():
            _assert_object_schema_satisfies_strict_mode(subschema, f"{path}.properties.{key}")
    if schema.get("type") == "array" and "items" in schema:
        _assert_object_schema_satisfies_strict_mode(schema["items"], f"{path}.items")


def test_tool_schema_satisfies_openai_strict_mode_everywhere():
    assert _RCA_TOOL_SCHEMA["strict"] is True
    assert _RCA_TOOL_SCHEMA["input_schema"]["type"] == "object"
    _assert_object_schema_satisfies_strict_mode(_RCA_TOOL_SCHEMA["input_schema"])
