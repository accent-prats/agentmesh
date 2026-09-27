from __future__ import annotations

from datetime import datetime, timezone

from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.models.taxonomy import CauseFamily
from culprit.pipeline.fingerprint import cluster_run
from culprit.pipeline.rules import evaluate_rules


def _machine(name="vm-1", os_family=OSFamily.LINUX) -> MachineIdentity:
    return MachineIdentity(
        vm_id=f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}",
        vm_name=name,
        resource_group="rg",
        subscription_id="s",
        os_family=os_family,
    )


def _bundle(machine, outcome, events) -> EvidenceBundle:
    return EvidenceBundle(
        run_id="run-1", machine=machine, outcome=outcome, timeline=events,
        collection_started_at=datetime.now(timezone.utc),
    )


def _cluster_for(bundle):
    return cluster_run("run-1", [bundle])[0]


def _ev(source, kind, summary, detail, ref="ref") -> TimelineEvent:
    return TimelineEvent(ts=datetime.now(timezone.utc), source=source, kind=kind, summary=summary, detail=detail, raw_ref=ref)


def test_disk_exhaustion_fires_with_corroborating_write_failure():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="PackageManagerFailure", packages_failed=["linux-image-5.15.0-91-generic"])
    events = [
        _ev(Source.DATADOG_METRIC, "metric_trend", "disk high", {"disk_low": True, "mount": "/boot"}, "dd:1"),
        _ev(Source.GUEST_LINUX, "package_manager_log", "gzip: stdout: No space left on device", {"write_failure": True, "disk_low": True}, "guest:1"),
    ]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is not None
    assert result.cause_family == CauseFamily.CAPACITY
    assert result.confidence >= 0.8
    assert all(step.evidence_refs for step in result.causal_chain)


def test_disk_exhaustion_abstains_without_write_failure_corroboration():
    """A low-disk metric alone, with no actual write failure in the guest
    log, must NOT fire the rule - this is the over-firing guard."""
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="ExtensionOperationFailed")
    events = [_ev(Source.DATADOG_METRIC, "metric_trend", "disk high", {"disk_low": True, "mount": "/boot"}, "dd:1")]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is None  # falls through to deep RCA - this is not the same as no rule matching wrongly


def test_agent_not_ready_fires_on_heartbeat_gap():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="ExtensionOperationFailed")
    events = [_ev(Source.AZURE_MONITOR, "heartbeat_gap", "no heartbeat", {"agent_unresponsive": True}, "hb:1")]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is not None
    assert result.cause_family == CauseFamily.AGENT_EXTENSION


def test_orchestration_mismatch_fires():
    machine = _machine()
    outcome = PatchOutcome(status="Skipped", error_code="Skipped")
    events = [_ev(Source.AZURE_CONTROL_PLANE, "patch_mode", "mode mismatch", {"mode": "AutomaticByOS"}, "pm:1")]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is not None
    assert result.cause_family == CauseFamily.CONFIGURATION
    assert result.confidence >= 0.9


def test_orchestration_mismatch_does_not_fire_when_mode_is_correct():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="PackageManagerFailure")
    events = [_ev(Source.AZURE_CONTROL_PLANE, "patch_mode", "mode ok", {"mode": "AutomaticByPlatform"}, "pm:1")]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is None


def test_reboot_starvation_requires_both_pending_and_never_setting():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="PackageManagerFailure")
    events_incomplete = [_ev(Source.GUEST_WINDOWS, "pending_reboot", "pending", {"pending_reboot": True}, "rb:1")]
    bundle_incomplete = _bundle(machine, outcome, events_incomplete)
    assert evaluate_rules(_cluster_for(bundle_incomplete), bundle_incomplete) is None

    events_complete = events_incomplete + [_ev(Source.AZURE_CONTROL_PLANE, "maintenance_config", "reboot setting", {"reboot_setting": "Never"}, "rb:2")]
    bundle_complete = _bundle(machine, outcome, events_complete)
    result = evaluate_rules(_cluster_for(bundle_complete), bundle_complete)
    assert result is not None
    assert result.cause_family == CauseFamily.REBOOT


def test_package_manager_locked_fires():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="PackageManagerFailure")
    events = [_ev(Source.GUEST_LINUX, "lock_state", "lock held", {"lock_held": True, "lock_holder_pid": "4821"}, "lk:1")]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is not None
    assert result.cause_family == CauseFamily.PACKAGE_MANAGER_STATE
    assert "4821" in result.causal_chain[0].statement


def test_machine_unavailable_fires():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="VmNotFound")
    events = [_ev(Source.AZURE_CONTROL_PLANE, "power_state", "deallocated", {"power_off": True}, "pw:1")]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is not None
    assert result.cause_family == CauseFamily.WINDOW_SCHEDULING


def test_source_entitlement_expired_fires():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="PackageManagerFailure")
    events = [_ev(Source.GUEST_LINUX, "entitlement_state", "invalid", {"entitlement_expired": True}, "ent:1")]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is not None
    assert result.cause_family == CauseFamily.SOURCE_ENTITLEMENT
    assert result.remediation.phase2_candidate is False


def test_permission_policy_fires():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="0x80070005")
    events = [_ev(Source.AZURE_CONTROL_PLANE, "activity_log", "policy denied", {"policy_block": True}, "pol:1")]
    bundle = _bundle(machine, outcome, events)
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is not None
    assert result.cause_family == CauseFamily.PERMISSION_POLICY


def test_window_exceeded_never_settled_by_a_rule():
    """Proposal Section 7: window exhaustion is always a symptom that must
    escalate to deep RCA - no rule should claim it."""
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="MaintenanceWindowExceeded")
    bundle = _bundle(machine, outcome, [])
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is None


def test_ambiguous_evidence_falls_through_to_none():
    machine = _machine()
    outcome = PatchOutcome(status="Failed", error_code="UnknownError")
    bundle = _bundle(machine, outcome, [])
    result = evaluate_rules(_cluster_for(bundle), bundle)
    assert result is None
