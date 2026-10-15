from __future__ import annotations

from datetime import datetime, timezone

from culprit.collectors.base import CollectionResult
from culprit.models.evidence import MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.pipeline.normalize import merge_bundle


def _machine() -> MachineIdentity:
    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )


def _ev(ts, ref) -> TimelineEvent:
    return TimelineEvent(ts=ts, source=Source.GUEST_LINUX, kind="k", summary="s", detail={}, raw_ref=ref)


def test_merges_events_from_multiple_sources_sorted():
    now = datetime.now(timezone.utc)
    results = {
        Source.AZURE_CONTROL_PLANE: CollectionResult(
            events=[_ev(now, "a")],
            outcome=PatchOutcome(status="Failed", error_code="PackageManagerFailure"),
        ),
        Source.GUEST_LINUX: CollectionResult(events=[_ev(now.replace(microsecond=0), "b")]),
    }
    bundle = merge_bundle("run-1", _machine(), results)
    assert len(bundle.timeline) == 2
    assert bundle.outcome.status == "Failed"
    assert bundle.sources_succeeded == [Source.AZURE_CONTROL_PLANE, Source.GUEST_LINUX]


def test_collector_error_becomes_a_collection_gap_not_a_crash():
    results = {
        Source.AZURE_CONTROL_PLANE: CollectionResult(
            events=[], outcome=PatchOutcome(status="Failed", error_code="X")
        ),
        Source.GUEST_LINUX: CollectionResult(events=[], error="Run Command timed out after 30s"),
    }
    bundle = merge_bundle("run-1", _machine(), results)
    assert any("timed out" in g for g in bundle.collection_gaps)
    assert Source.GUEST_LINUX not in bundle.sources_succeeded


def test_missing_control_plane_outcome_synthesizes_placeholder_and_gap():
    results = {Source.GUEST_LINUX: CollectionResult(events=[])}
    bundle = merge_bundle("run-1", _machine(), results)
    assert bundle.outcome.status == "Unknown"
    assert any("no patch outcome" in g for g in bundle.collection_gaps)


def test_patch_extension_status_is_accumulated_across_collectors():
    results = {
        Source.AZURE_CONTROL_PLANE: CollectionResult(events=[], outcome=PatchOutcome(status="Failed")),
        Source.GUEST_LINUX: CollectionResult(
            events=[],
            patch_extension_status=[{"source": "guest_linux", "status": "error", "message": "disk full"}],
        ),
    }
    bundle = merge_bundle("run-1", _machine(), results)
    assert bundle.patch_extension_status == [{"source": "guest_linux", "status": "error", "message": "disk full"}]


def test_duplicate_events_are_deduped():
    now = datetime.now(timezone.utc)
    ev = _ev(now, "same-ref")
    results = {
        Source.GUEST_LINUX: CollectionResult(events=[ev, ev]),
        Source.AZURE_CONTROL_PLANE: CollectionResult(events=[], outcome=PatchOutcome(status="Failed")),
    }
    bundle = merge_bundle("run-1", _machine(), results)
    assert len(bundle.timeline) == 1
