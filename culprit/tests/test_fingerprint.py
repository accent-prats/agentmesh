from __future__ import annotations

from datetime import datetime, timezone

from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.pipeline.fingerprint import build_fingerprint, cluster_run, fingerprint_id


def _machine(name: str, os_family=OSFamily.LINUX) -> MachineIdentity:
    return MachineIdentity(
        vm_id=f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}",
        vm_name=name,
        resource_group="rg",
        subscription_id="s",
        os_family=os_family,
    )


def _bundle(name: str, error_code: str, package: str | None = None, disk_low: bool = False) -> EvidenceBundle:
    machine = _machine(name)
    timeline = []
    if disk_low:
        timeline.append(
            TimelineEvent(
                ts=datetime.now(timezone.utc),
                source=Source.DATADOG_METRIC,
                kind="metric_trend",
                summary="disk low",
                detail={"disk_low": True, "mount": "/boot"},
                raw_ref=f"dd:{name}",
            )
        )
    return EvidenceBundle(
        run_id="run-1",
        machine=machine,
        outcome=PatchOutcome(status="Failed", error_code=error_code, packages_failed=[package] if package else []),
        timeline=timeline,
        collection_started_at=datetime.now(timezone.utc),
    )


def test_identical_failures_collapse_into_one_cluster():
    bundles = [
        _bundle("vm-1", "PackageManagerFailure", "linux-image-5.15.0-91-generic", disk_low=True),
        _bundle("vm-2", "PackageManagerFailure", "linux-image-5.15.0-92-generic", disk_low=True),
        _bundle("vm-3", "PackageManagerFailure", "linux-image-5.15.0-93-generic", disk_low=True),
    ]
    clusters = cluster_run("run-1", bundles)
    assert len(clusters) == 1
    assert clusters[0].size == 3


def test_different_failures_stay_in_separate_clusters():
    bundles = [
        _bundle("vm-1", "PackageManagerFailure", "linux-image-5.15.0-91-generic", disk_low=True),
        _bundle("vm-2", "MaintenanceWindowExceeded"),
    ]
    clusters = cluster_run("run-1", bundles)
    assert len(clusters) == 2


def test_successful_machines_are_excluded():
    bundles = [
        _bundle("vm-1", "PackageManagerFailure"),
    ]
    success = EvidenceBundle(
        run_id="run-1",
        machine=_machine("vm-2"),
        outcome=PatchOutcome(status="Succeeded"),
        timeline=[],
        collection_started_at=datetime.now(timezone.utc),
    )
    clusters = cluster_run("run-1", bundles + [success])
    total_members = sum(c.size for c in clusters)
    assert total_members == 1


def test_fingerprint_id_is_stable_across_runs():
    b1 = _bundle("vm-1", "PackageManagerFailure", "linux-image-5.15.0-91-generic", disk_low=True)
    b2 = _bundle("vm-9", "PackageManagerFailure", "linux-image-5.15.0-77-generic", disk_low=True)
    fp1 = build_fingerprint(b1)
    fp2 = build_fingerprint(b2)
    # Same error code, OS family, normalized target family, precondition -
    # different specific kernel version numbers - must fingerprint the same.
    assert fingerprint_id(fp1) == fingerprint_id(fp2)


def test_clusters_are_sorted_largest_first():
    bundles = (
        [_bundle(f"vm-a{i}", "PackageManagerFailure", "linux-image-5.15.0-91-generic", disk_low=True) for i in range(5)]
        + [_bundle(f"vm-b{i}", "MaintenanceWindowExceeded") for i in range(2)]
    )
    clusters = cluster_run("run-1", bundles)
    assert clusters[0].size == 5
    assert clusters[1].size == 2


def test_representative_and_cluster_key_present():
    bundles = [_bundle("vm-1", "PackageManagerFailure", "linux-image-5.15.0-91-generic", disk_low=True)]
    clusters = cluster_run("run-1", bundles)
    assert clusters[0].representative_vm_id == bundles[0].machine.vm_id
    assert len(clusters[0].cluster_key) == 16
