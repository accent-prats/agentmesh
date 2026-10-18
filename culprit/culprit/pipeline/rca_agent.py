"""The deep RCA agent (proposal Section 7): Claude reasoning over the
ambiguous tail the rule engine couldn't settle.

Design choices that map directly to the proposal's "hard constraint":

  - Output is schema-enforced via a strict tool definition
    (`submit_rca_finding`, `strict: true`), not requested via prompt alone.
    `additionalProperties: false` + `required` means a structurally
    incomplete answer is rejected by the API itself before it reaches us.
  - Every `evidence_refs` entry must be non-empty (enforced again at the
    Pydantic layer in culprit/models/rca.py) - "no citation, no claim".
  - `missing_evidence` is a first-class field, not an afterthought: a
    non-empty list is a request the orchestrator acts on by re-dispatching
    collectors for exactly those signals (see culprit/pipeline/orchestrator.py),
    rather than the agent silently guessing.

Uses `claude-opus-5` by default - this is the one call in the pipeline
that's actually hard (reading a messy log in context, correlating a
Datadog metric with an Activity Log entry, and reasoning about what that
implies), so it's exactly the kind of task worth the frontier model,
per the proposal's "rules first, model for the tail" design.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Protocol

from pydantic import ValidationError

from culprit.models.cluster import Cluster
from culprit.models.evidence import EvidenceBundle
from culprit.models.rca import RCAResult, ResultOrigin, format_unverifiable_reason
from culprit.models.taxonomy import CauseFamily

log = logging.getLogger(__name__)


def _safe_exc_summary(exc: BaseException) -> str:
    """A short, provably-secret-free description of an exception for a log
    line - just the exception class, plus an HTTP status code when one is
    actually available. Deliberately never `str(exc)`: found in review
    2026-10-16 that `httpx.HTTPStatusError`'s own string representation
    embeds the full request URL - which for a Gemini-backed client
    (shared/src/llm/gemini.py) carries the real API key in its query
    string, re-leaking exactly the secret the adapter's own logging was
    reviewed and fixed to redact, just via the exception message instead
    of a log argument. `self.client` here can be any provider's adapter
    (or the raw Anthropic SDK), so this stays conservative regardless of
    which one actually raised."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status is not None:
        return f"{type(exc).__name__}(status={status})"
    return type(exc).__name__


DEFAULT_MODEL = "claude-opus-5"

_TOOL_NAME = "submit_rca_finding"

_RCA_TOOL_SCHEMA: dict[str, Any] = {
    "name": _TOOL_NAME,
    "description": (
        "Submit the root-cause finding for this cluster of failed patch deployments. "
        "Call this exactly once, after you have reasoned through the evidence timeline."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cause_family": {"type": "string", "enum": [f.value for f in CauseFamily]},
            "title": {"type": "string", "description": "One-line summary of the root cause"},
            "causal_chain": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "order": {"type": "integer"},
                        "statement": {"type": "string"},
                        "evidence_refs": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                            "description": "raw_ref values copied verbatim from the evidence timeline",
                        },
                    },
                    "required": ["order", "statement", "evidence_refs"],
                    "additionalProperties": False,
                },
            },
            "ruled_out": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "candidate": {"type": "string"},
                        "reason": {"type": "string"},
                        "evidence_refs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "raw_ref values supporting why this was ruled out - empty array if none apply",
                        },
                    },
                    # Found 2026-10-18 from a real production 400: OpenAI's
                    # strict function-calling mode rejects any object schema
                    # whose `required` doesn't list every key in
                    # `properties` - "optional" here is expressed by the
                    # model supplying an empty array, not by omitting the
                    # key from `required` (models/rca.py::RuledOutCause's
                    # own `evidence_refs` already defaults to `[]`, so this
                    # doesn't change how an empty value is handled downstream).
                    "required": ["candidate", "reason", "evidence_refs"],
                    "additionalProperties": False,
                },
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "missing_evidence": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific additional signals that would raise confidence, e.g. "
                "'Datadog disk metric for the 14 days before the window' - empty if none needed",
            },
            "immediate_fix_steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "order": {"type": "integer"},
                        "instruction": {"type": "string"},
                        "expected_result": {
                            "type": "string",
                            "description": "What should be true after this step succeeds - empty string if not yet known",
                        },
                    },
                    # Same fix, same reason as "ruled_out" above - strict
                    # mode requires every property in `required`.
                    # models/rca.py::RemediationStep's own `expected_result`
                    # already defaults to "".
                    "required": ["order", "instruction", "expected_result"],
                    "additionalProperties": False,
                },
            },
            "immediate_risk": {"type": "string", "enum": ["low", "medium", "high"]},
            "immediate_scope": {"type": "string", "enum": ["per_machine", "fleet_wide"]},
            "preventive_fix": {"type": "string"},
            "preventive_risk": {"type": "string", "enum": ["low", "medium", "high"]},
            "rollback": {"type": "string"},
            "phase2_candidate": {"type": "boolean"},
            "phase2_rationale": {"type": "string"},
        },
        "required": [
            "cause_family", "title", "causal_chain", "ruled_out", "confidence",
            "missing_evidence", "immediate_fix_steps", "immediate_risk",
            "immediate_scope", "preventive_fix", "preventive_risk",
            "rollback", "phase2_candidate", "phase2_rationale",
        ],
        "additionalProperties": False,
    },
    "strict": True,
}


class AnthropicClientLike(Protocol):
    """The minimal surface this module depends on - narrow on purpose so a
    test double only has to implement `messages.create(**kwargs) -> response`
    where `response` exposes `.content` (list of blocks with `.type`,
    and `.input`/`.name` for tool_use blocks) and `.stop_reason`."""

    messages: Any


def _build_system_prompt() -> str:
    return (
        "You are Culprit's deep root-cause-analysis agent for Azure Update Manager patch "
        "failures. You are given the full evidence timeline for one cluster of machines that "
        "failed a patch deployment for what a deterministic fingerprint says is the same reason, "
        "plus a note on which deterministic rules almost fired but didn't (and why), plus "
        "retrieved reference material (vendor documentation and this organization's own "
        "previously-resolved incidents).\n\n"
        "Hard rules:\n"
        "1. Every statement in your causal chain MUST cite at least one evidence_refs value "
        "copied verbatim from the timeline you were given. Never invent a raw_ref.\n"
        "2. If the evidence is insufficient to reach a confident conclusion, say so: set a low "
        "confidence and populate missing_evidence with exactly what you would need. Do not "
        "produce a plausible-sounding guess to fill the gap - a low-confidence 'I don't know yet, "
        "fetch me X' is the correct and expected answer in that case.\n"
        "3. Explicitly state what you ruled out and why - not just what you concluded.\n"
        "4. Separate the immediate fix (what makes this machine compliant now) from the "
        "preventive fix (what stops this cause recurring next cycle) - conflating them is how a "
        "cause comes back next month while everyone believes it was fixed.\n"
        "5. Only mark phase2_candidate true if the immediate fix is mechanical, bounded, "
        "verifiable, and has a clear rollback - reboots, network changes, and anything needing "
        "judgment about running workloads should be false.\n\n"
        "Call the submit_rca_finding tool exactly once with your complete finding."
    )


def _build_user_prompt(
    cluster: Cluster,
    representative: EvidenceBundle,
    near_misses: list[str],
    retrieval_context: str,
) -> str:
    parts = [
        f"CLUSTER: {cluster.cluster_id} ({cluster.size} machine(s), fingerprint key {cluster.cluster_key})",
        f"Representative machine: {representative.machine.vm_name} ({representative.machine.os_family.value})",
        f"Patch outcome: status={representative.outcome.status} error_code={representative.outcome.error_code}",
        # sources_attempted/succeeded were already populated by
        # pipeline/normalize.py::merge_bundle but never read anywhere
        # downstream - surfacing them here tells the model what evidence
        # universe this deployment even has (e.g. no Datadog configured
        # at all) rather than leaving it to infer that from collection_gaps
        # prose alone.
        f"Evidence sources attempted: {', '.join(s.value for s in representative.sources_attempted) or '(none)'} "
        f"| succeeded: {', '.join(s.value for s in representative.sources_succeeded) or '(none)'}",
        "",
        "EVIDENCE TIMELINE (each line ends with its raw_ref - cite these exactly):",
        representative.timeline_sorted() and representative.render_timeline_text() or "(no timeline events collected)",
    ]
    if representative.collection_gaps:
        parts += ["", "COLLECTION GAPS (evidence that could not be gathered):", *[f"- {g}" for g in representative.collection_gaps]]
    if near_misses:
        parts += ["", "RULES THAT ALMOST FIRED (and why they abstained):", *[f"- {n}" for n in near_misses]]
    if retrieval_context:
        parts += ["", "RETRIEVED REFERENCE MATERIAL:", retrieval_context]
    return "\n".join(parts)


class DeepRCAAgent:
    def __init__(self, client: AnthropicClientLike | None = None, model: str = DEFAULT_MODEL):
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        self.client = client
        self.model = model

    def diagnose(
        self,
        cluster: Cluster,
        representative: EvidenceBundle,
        near_misses: list[str] | None = None,
        retrieval_context: str = "",
    ) -> RCAResult:
        system = _build_system_prompt()
        user_prompt = _build_user_prompt(cluster, representative, near_misses or [], retrieval_context)

        # Found 2026-10-16, tracing a real production timeout: this call
        # had no logging of its own at all - once it was confirmed to be
        # the thing actually hanging/failing (via its own exception's
        # traceback), there was still no way to tell from logs alone
        # which cluster/machine a given slow or failed call belonged to,
        # or how long it ran before failing. prompt_chars is a cheap
        # proxy for "is this cluster's evidence unusually large" without
        # logging the prompt content itself.
        log.info(
            "RCA diagnose starting: cluster=%s machine=%s model=%s prompt_chars=%d",
            cluster.cluster_id, representative.machine.vm_name, self.model, len(user_prompt),
        )
        started = time.monotonic()
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=8000,
                thinking={"type": "adaptive"},
                system=system,
                tools=[_RCA_TOOL_SCHEMA],
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception as exc:
            log.warning(
                "RCA diagnose call failed: cluster=%s machine=%s after %.1fs (%s)",
                cluster.cluster_id, representative.machine.vm_name, time.monotonic() - started, _safe_exc_summary(exc),
            )
            raise
        log.info(
            "RCA diagnose call returned: cluster=%s machine=%s after %.1fs",
            cluster.cluster_id, representative.machine.vm_name, time.monotonic() - started,
        )

        tool_call = next((b for b in response.content if getattr(b, "type", None) == "tool_use" and getattr(b, "name", None) == _TOOL_NAME), None)
        if tool_call is None:
            return _unresolved_result(cluster, reason=format_unverifiable_reason(
                "The analysis assistant didn't return a structured finding for this cluster.",
                "Model did not call submit_rca_finding",
            ))

        raw_input = tool_call.input
        if isinstance(raw_input, str):  # defensive: some transports hand back a JSON string
            try:
                raw_input = json.loads(raw_input)
            except json.JSONDecodeError as exc:
                return _unresolved_result(cluster, reason=format_unverifiable_reason(
                    "The analysis assistant's response couldn't be read.",
                    f"Tool input was not valid JSON: {exc}",
                ))

        try:
            result = _to_rca_result(cluster.cluster_id, raw_input)
        except ValidationError as exc:
            log.warning("RCA result failed schema validation for cluster %s: %s", cluster.cluster_id, exc)
            return _unresolved_result(cluster, reason=format_unverifiable_reason(
                "The analysis assistant's response didn't match the expected format.",
                f"Model output failed validation: {exc}",
            ))

        # Found in review 2026-09-27: the Pydantic validator on CausalStep
        # only checks evidence_refs is non-empty, never that a ref actually
        # exists in the bundle the model was given - a hallucinated but
        # well-formed raw_ref passed cleanly. Cross-check it here instead.
        bad_refs = _fabricated_refs(result, representative)
        if bad_refs:
            log.warning(
                "RCA result for cluster %s cited evidence_refs absent from the collected timeline: %s",
                cluster.cluster_id, bad_refs,
            )
            # Found 2026-10-18 from a real user complaint: showing the raw
            # fabricated ref (e.g. "vendor_doc") under a "what the RCA
            # agent said it would need for more confidence" heading is
            # both wrong (nothing is missing - the model's answer was
            # discarded) and meaningless to a non-technical reader. See
            # format_unverifiable_reason's own comment in models/rca.py.
            return _unresolved_result(cluster, reason=format_unverifiable_reason(
                "The analysis assistant proposed an explanation but cited evidence that doesn't "
                "actually exist in what was collected for this machine, so the result was discarded "
                "rather than shown as a confirmed finding.",
                f"Fabricated evidence_refs: {bad_refs}",
            ))

        return result


def _to_rca_result(cluster_id: str, data: dict[str, Any]) -> RCAResult:
    from culprit.models.rca import CausalStep, RemediationPlaybook, RemediationStep, RiskLevel, RuledOutCause

    return RCAResult(
        cluster_id=cluster_id,
        origin=ResultOrigin.DEEP_RCA,
        cause_family=CauseFamily(data["cause_family"]),
        title=data["title"],
        causal_chain=[CausalStep(**step) for step in data["causal_chain"]],
        ruled_out=[RuledOutCause(**r) for r in data.get("ruled_out", [])],
        confidence=data["confidence"],
        missing_evidence=data.get("missing_evidence", []),
        remediation=RemediationPlaybook(
            immediate_fix=[RemediationStep(**s) for s in data.get("immediate_fix_steps", [])],
            immediate_risk=RiskLevel(data.get("immediate_risk", "low")),
            immediate_scope=data.get("immediate_scope", "per_machine"),
            preventive_fix=data.get("preventive_fix", ""),
            preventive_risk=RiskLevel(data.get("preventive_risk", "medium")),
            rollback=data.get("rollback", ""),
            phase2_candidate=data.get("phase2_candidate", False),
            phase2_rationale=data.get("phase2_rationale", ""),
        ),
    )


def _fabricated_refs(result: RCAResult, bundle: EvidenceBundle) -> list[str]:
    """Every evidence_ref the model cited that isn't a real raw_ref in the
    bundle it was given - see the diagnose() call site for why this check
    exists on top of the Pydantic non-empty validation."""
    valid_refs = {e.raw_ref for e in bundle.timeline}
    return [ref for step in result.causal_chain for ref in step.evidence_refs if ref not in valid_refs]


def _unresolved_result(cluster: Cluster, reason: str) -> RCAResult:
    return RCAResult(
        cluster_id=cluster.cluster_id,
        origin=ResultOrigin.DEEP_RCA,
        cause_family=CauseFamily.UNRESOLVED,
        title="Insufficient evidence for a confident root cause",
        causal_chain=[],
        confidence=0.0,
        missing_evidence=[reason],
    )
