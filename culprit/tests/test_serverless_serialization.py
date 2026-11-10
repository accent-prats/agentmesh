"""culprit/serverless/serialization.py - proves the dict<->model round
trip is lossless for every type that crosses a Durable Functions activity
boundary. Built against real model instances, not just "the function
exists" - a round trip through `.model_dump(mode="json")` is exactly
where a datetime/enum field could silently lose precision or type if
these ever stopped matching.
"""
from __future__ import annotations

from datetime import datetime, timezone

from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
from culprit.models.evidence import (
    EvidenceBundle,
    MachineIdentity,
    OSFamily,
    PatchOutcome,
    Source,
    TimelineEvent,
)
from culprit.models.patch_run import PatchRun, TriggerMode
from culprit.models.rca import CausalStep, CauseFamily, RCAResult, ResultOrigin
from culprit.serverless.serialization import (
    bundle_from_dict,
    bundle_to_dict,
    cluster_from_dict,
    cluster_to_dict,
    machine_from_dict,
    machine_to_dict,
    patch_run_from_dict,
    patch_run_to_dict,
    rca_result_from_dict,
    rca_result_to_dict,
)


def _machine() -> MachineIdentity:
    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        run_id="run-1", machine=_machine(),
        outcome=PatchOutcome(status="Failed", error_code="PT_FAIL", started_at=datetime(2026, 11, 1, tzinfo=timezone.utc)),
        timeline=[TimelineEvent(ts=datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc), source=Source.AZURE_CONTROL_PLANE, kind="api_result", summary="failed", raw_ref="ref-1")],
        collection_started_at=datetime(2026, 11, 1, 1, 0, tzinfo=timezone.utc),
        sources_attempted=[Source.AZURE_CONTROL_PLANE], sources_succeeded=[Source.AZURE_CONTROL_PLANE],
    )


def _cluster() -> Cluster:
    return Cluster(
        cluster_id="cluster-1", run_id="run-1", cluster_key="key-1",
        fingerprint=Fingerprint(error_code_normalized="pt_fail", os_family=OSFamily.LINUX, failing_target="pkg"),
        members=[ClusterMember(vm_id=_machine().vm_id, vm_name="vm-1")],
        representative_vm_id=_machine().vm_id,
    )


def _rca_result() -> RCAResult:
    return RCAResult(
        cluster_id="cluster-1", origin=ResultOrigin.RULE_ENGINE, cause_family=CauseFamily.SOURCE_ENTITLEMENT,
        title="repo unreachable", causal_chain=[CausalStep(order=1, statement="repo unreachable", evidence_refs=["ref-1"])],
        confidence=0.9,
    )


def _patch_run() -> PatchRun:
    return PatchRun(
        run_id="live-1", maintenance_configuration_id="cfg", subscription_id="s", scope_name="scheduled",
        started_at=datetime(2026, 11, 1, tzinfo=timezone.utc), total_machines=5, trigger_mode=TriggerMode.SCHEDULED,
    )


def test_machine_identity_round_trips():
    m = _machine()
    assert machine_from_dict(machine_to_dict(m)) == m


def test_evidence_bundle_round_trips():
    b = _bundle()
    assert bundle_from_dict(bundle_to_dict(b)) == b


def test_cluster_round_trips():
    c = _cluster()
    assert cluster_from_dict(cluster_to_dict(c)) == c


def test_rca_result_round_trips():
    r = _rca_result()
    assert rca_result_from_dict(rca_result_to_dict(r)) == r


def test_patch_run_round_trips():
    r = _patch_run()
    assert patch_run_from_dict(patch_run_to_dict(r)) == r
