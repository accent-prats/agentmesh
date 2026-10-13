"""The deterministic rulebook (proposal Section 7).

Every rule is a plain predicate over a Cluster's representative
EvidenceBundle: it fires only when its evidence is present, and it
abstains - never guesses - when it isn't. Rules run before the RCA agent
and settle every cause that's unambiguous from the evidence; whatever is
left over (a `None` result) is exactly the ambiguous tail that goes to
deep RCA in culprit/pipeline/rca_agent.py.

This module has no dependency on Anthropic, or any model at all - that's
the point. It's auditable, instant, free, and structurally incapable of
hallucinating.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from culprit.models.cluster import Cluster
from culprit.models.evidence import EvidenceBundle, OSFamily, Source
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

_DISK_THRESHOLD_FREE_RATIO = 0.05  # below this, "low disk" fires
_AGENT_STALE_HOURS = 2.0


@dataclass
class RuleContext:
    cluster: Cluster
    representative: EvidenceBundle


RuleFn = Callable[[RuleContext], RCAResult | None]


def _find(events, source: Source, kind: str):
    return [e for e in events if e.source == source and e.kind == kind]


def _has_detail_flag(bundle: EvidenceBundle, flag: str) -> tuple[bool, list[str]]:
    """Returns (fired, evidence_refs) for a boolean detail flag anywhere in
    the timeline - used by the several rules that key off a single
    precondition token collectors already normalised."""
    refs = [e.raw_ref for e in bundle.timeline if e.detail.get(flag)]
    return (bool(refs), refs)


def rule_disk_exhaustion(ctx: RuleContext) -> RCAResult | None:
    bundle = ctx.representative
    fired, refs = _has_detail_flag(bundle, "disk_low")
    if not fired:
        return None
    # Require corroborating evidence of an actual write failure, not just a
    # low-disk metric - otherwise this over-fires on machines that were low
    # on space but failed for an unrelated reason.
    write_failure_refs = [
        e.raw_ref
        for e in bundle.timeline
        if e.detail.get("write_failure") or "no space left on device" in e.summary.lower()
    ]
    if not write_failure_refs:
        return None

    mount = next((e.detail.get("mount") for e in bundle.timeline if e.detail.get("disk_low")), "/")
    return RCAResult(
        cluster_id=ctx.cluster.cluster_id,
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.CAPACITY,
        title=f"Disk exhaustion on {mount} blocked the package/update transaction",
        causal_chain=[
            CausalStep(order=1, statement=f"Free space on {mount} was below threshold at run time", evidence_refs=refs),
            CausalStep(order=2, statement="The package manager or update agent failed a write for lack of space", evidence_refs=write_failure_refs),
        ],
        confidence=0.9,
        remediation=RemediationPlaybook(
            immediate_fix=[
                RemediationStep(order=1, instruction=f"Free space on {mount} (e.g. prune old kernels, clear temp/cache directories)", expected_result=f"{mount} has at least 200MB free"),
                RemediationStep(order=2, instruction="Resume or re-run the interrupted package transaction", expected_result="Transaction completes without a space error"),
                RemediationStep(order=3, instruction="Re-run patch assessment", expected_result="Machine reports compliant"),
            ],
            immediate_risk=RiskLevel.LOW,
            immediate_scope="per_machine",
            preventive_fix=f"Add a retention/cleanup policy for {mount} and a monitor with an actual alert route so this doesn't silently refill.",
            preventive_risk=RiskLevel.MEDIUM,
            phase2_candidate=True,
            phase2_rationale="Mechanical, bounded, verifiable, and trivially reversible.",
            automation_params={"mount": mount},
        ),
    )


def rule_agent_not_ready(ctx: RuleContext) -> RCAResult | None:
    bundle = ctx.representative
    heartbeat_gaps = [e for e in bundle.timeline if e.kind == "heartbeat_gap"]
    stale_version = [e for e in bundle.timeline if e.detail.get("agent_stale") or e.detail.get("agent_unresponsive")]
    if not heartbeat_gaps and not stale_version:
        return None

    refs = [e.raw_ref for e in (heartbeat_gaps or stale_version)]
    return RCAResult(
        cluster_id=ctx.cluster.cluster_id,
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.AGENT_EXTENSION,
        title="Guest/Arc agent was not reachable during the maintenance window",
        causal_chain=[
            CausalStep(order=1, statement="Heartbeat/agent telemetry shows a gap spanning the maintenance window", evidence_refs=refs),
            CausalStep(order=2, statement="The patch extension could not reach the guest to execute or report", evidence_refs=refs),
        ],
        confidence=0.85,
        remediation=RemediationPlaybook(
            immediate_fix=[
                RemediationStep(order=1, instruction="Check VM power/network state and restart the guest agent (waagent / GuestAgent service)", expected_result="Heartbeat resumes"),
                RemediationStep(order=2, instruction="Re-run the patch job for this machine", expected_result="Job completes and reports a result"),
            ],
            immediate_risk=RiskLevel.LOW,
            preventive_fix="Alert on heartbeat gaps proactively, before the next maintenance window opens.",
            phase2_candidate=True,
            phase2_rationale="Restarting a stalled agent is mechanical and safe to automate first.",
        ),
    )


def rule_reboot_starvation(ctx: RuleContext) -> RCAResult | None:
    bundle = ctx.representative
    fired, refs = _has_detail_flag(bundle, "pending_reboot")
    if not fired:
        return None
    never_reboot = [e for e in bundle.timeline if e.detail.get("reboot_setting") == "Never"]
    if not never_reboot:
        return None

    return RCAResult(
        cluster_id=ctx.cluster.cluster_id,
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.REBOOT,
        title="A pending reboot from a prior cycle blocked this cycle, and reboot is disabled",
        causal_chain=[
            CausalStep(order=1, statement="A reboot was already pending before this run started", evidence_refs=refs),
            CausalStep(order=2, statement="The maintenance configuration's rebootSetting is 'Never', so the pending reboot was never cleared", evidence_refs=[e.raw_ref for e in never_reboot]),
        ],
        confidence=0.85,
        remediation=RemediationPlaybook(
            immediate_fix=[
                RemediationStep(order=1, instruction="Schedule an explicit reboot for this machine in a change window", expected_result="Pending-reboot flag clears"),
                RemediationStep(order=2, instruction="Re-run assessment", expected_result="Machine reports compliant"),
            ],
            immediate_risk=RiskLevel.MEDIUM,
            preventive_fix="Move this machine (or class of machine) to 'IfRequired' reboot setting, or schedule a dedicated reboot window.",
            phase2_candidate=False,
            phase2_rationale="Reboots touch running workloads - hold this family for human approval even after other families are promoted.",
        ),
    )


def rule_orchestration_mismatch(ctx: RuleContext) -> RCAResult | None:
    bundle = ctx.representative
    mode_events = [e for e in bundle.timeline if e.kind == "patch_mode" and e.detail.get("mode") not in (None, "AutomaticByPlatform")]
    if not mode_events:
        return None

    return RCAResult(
        cluster_id=ctx.cluster.cluster_id,
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.CONFIGURATION,
        title=f"Patch orchestration mode is '{mode_events[0].detail.get('mode')}', not AutomaticByPlatform",
        causal_chain=[
            CausalStep(
                order=1,
                statement=f"This machine's patch mode is '{mode_events[0].detail.get('mode')}', so a scheduled Update Manager run cannot orchestrate it",
                evidence_refs=[e.raw_ref for e in mode_events],
            )
        ],
        confidence=0.95,
        remediation=RemediationPlaybook(
            immediate_fix=[
                RemediationStep(order=1, instruction="Set the VM's patch orchestration mode to AutomaticByPlatform", expected_result="Machine becomes eligible for scheduled runs"),
            ],
            immediate_risk=RiskLevel.LOW,
            immediate_scope="fleet_wide",
            preventive_fix="Enforce patch mode via Azure Policy at VM creation so this can't drift again.",
            phase2_candidate=True,
            phase2_rationale="A single, well-understood configuration write with an obvious rollback.",
        ),
    )


def rule_package_manager_locked(ctx: RuleContext) -> RCAResult | None:
    bundle = ctx.representative
    fired, refs = _has_detail_flag(bundle, "lock_held")
    if not fired:
        return None

    holder = next((e.detail.get("lock_holder_pid") for e in bundle.timeline if e.detail.get("lock_held")), None)
    return RCAResult(
        cluster_id=ctx.cluster.cluster_id,
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.PACKAGE_MANAGER_STATE,
        title="Package manager lock was held by another process for the duration of the window",
        causal_chain=[
            CausalStep(
                order=1,
                statement=f"dpkg/rpm lock was held{f' by pid {holder}' if holder else ''} throughout the window",
                evidence_refs=refs,
            )
        ],
        confidence=0.8,
        remediation=RemediationPlaybook(
            immediate_fix=[
                RemediationStep(order=1, instruction="Identify and, if safe, terminate the process holding the lock", expected_result="Lock releases"),
                RemediationStep(order=2, instruction="Run 'dpkg --configure -a' (or the rpm/yum equivalent) to complete any interrupted transaction", expected_result="Package manager returns to a clean state"),
            ],
            immediate_risk=RiskLevel.MEDIUM,
            preventive_fix="Investigate what recurringly holds this lock (unattended-upgrades overlap, config-management run) and stagger it away from the maintenance window.",
            phase2_candidate=False,
            phase2_rationale="Killing an unknown process is not safe to fully automate without knowing what held the lock.",
        ),
    )


def rule_machine_unavailable(ctx: RuleContext) -> RCAResult | None:
    bundle = ctx.representative
    fired, refs = _has_detail_flag(bundle, "power_off")
    if not fired:
        return None

    return RCAResult(
        cluster_id=ctx.cluster.cluster_id,
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.WINDOW_SCHEDULING,
        title="Machine was deallocated or stopped during the maintenance window",
        causal_chain=[
            CausalStep(order=1, statement="Power state was deallocated/stopped for some or all of the window", evidence_refs=refs)
        ],
        confidence=0.9,
        remediation=RemediationPlaybook(
            immediate_fix=[
                RemediationStep(order=1, instruction="Re-run the patch job once the machine is powered on", expected_result="Job completes normally"),
            ],
            immediate_risk=RiskLevel.LOW,
            preventive_fix="Exclude routinely-deallocated machines (dev/test auto-shutdown) from the schedule, or align the schedule to their uptime window.",
            phase2_candidate=True,
            phase2_rationale="Re-queuing a job is mechanical.",
        ),
    )


def rule_source_entitlement(ctx: RuleContext) -> RCAResult | None:
    bundle = ctx.representative
    repo = [e for e in bundle.timeline if e.detail.get("repo_unreachable")]
    entitlement = [e for e in bundle.timeline if e.detail.get("entitlement_expired")]
    if not repo and not entitlement:
        return None

    refs = [e.raw_ref for e in (repo + entitlement)]
    if entitlement:
        title = "Subscription/entitlement lapsed, blocking access to the update source"
        chain_stmt = "Repository access requires an entitlement (e.g. RHSM) that has expired"
    else:
        title = "Update source unreachable during the window"
        chain_stmt = "The configured repository/WSUS endpoint did not respond during the window"

    return RCAResult(
        cluster_id=ctx.cluster.cluster_id,
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.SOURCE_ENTITLEMENT,
        title=title,
        causal_chain=[CausalStep(order=1, statement=chain_stmt, evidence_refs=refs)],
        confidence=0.85,
        remediation=RemediationPlaybook(
            immediate_fix=[
                RemediationStep(order=1, instruction="Renew the entitlement or restore repository reachability" if entitlement else "Confirm DNS/network path and repository health, then retry", expected_result="Repository responds normally"),
                RemediationStep(order=2, instruction="Re-run the patch job", expected_result="Job completes"),
            ],
            immediate_risk=RiskLevel.LOW,
            preventive_fix="Alert on entitlement expiry ahead of time" if entitlement else "Add a pre-flight repository reachability check before the window opens.",
            phase2_candidate=False,
            phase2_rationale="Entitlement renewal/network fixes usually need a human with the right access.",
        ),
    )


def rule_permission_policy(ctx: RuleContext) -> RCAResult | None:
    bundle = ctx.representative
    fired, refs = _has_detail_flag(bundle, "policy_block")
    access_denied = [e for e in bundle.timeline if "access_denied" in (e.detail.get("normalized_error") or "")]
    if not fired and not access_denied:
        return None

    all_refs = refs + [e.raw_ref for e in access_denied]
    return RCAResult(
        cluster_id=ctx.cluster.cluster_id,
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=CauseFamily.PERMISSION_POLICY,
        title="Azure Policy or a resource lock blocked the patch extension",
        causal_chain=[
            CausalStep(order=1, statement="A policy assignment or resource lock denied the extension operation", evidence_refs=all_refs)
        ],
        confidence=0.85,
        remediation=RemediationPlaybook(
            immediate_fix=[
                RemediationStep(order=1, instruction="Identify the blocking policy/lock via the Activity Log denial entry and add a scoped exemption", expected_result="Extension operation is permitted"),
            ],
            immediate_risk=RiskLevel.MEDIUM,
            preventive_fix="Review policy assignments for unintended overlap with the patch extension's required permissions.",
            phase2_candidate=False,
            phase2_rationale="Policy exemptions are a governance decision, not a mechanical fix.",
        ),
    )


# Order matters only for readability/debugging - each rule is independent
# and every cluster is checked against all of them, first match wins.
ALL_RULES: list[RuleFn] = [
    rule_orchestration_mismatch,
    rule_disk_exhaustion,
    rule_agent_not_ready,
    rule_reboot_starvation,
    rule_package_manager_locked,
    rule_machine_unavailable,
    rule_source_entitlement,
    rule_permission_policy,
]


def evaluate_rules(cluster: Cluster, representative: EvidenceBundle) -> RCAResult | None:
    """Run every rule against a cluster's representative evidence and
    return the first definitive verdict, or None if nothing fired -
    meaning this cluster escalates to deep RCA."""
    ctx = RuleContext(cluster=cluster, representative=representative)
    for rule in ALL_RULES:
        result = rule(ctx)
        if result is not None:
            return result
    return None
