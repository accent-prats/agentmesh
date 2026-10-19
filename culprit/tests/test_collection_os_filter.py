"""collect_all must not run guest_windows against a Linux machine or
guest_linux against a Windows one - wasted API calls that are guaranteed
to fail. Uses fake collectors that record whether they were invoked."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector
from culprit.models.evidence import MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.pipeline.collection import collect_all, recollect_targeted


@dataclass
class RecordingCollector(Collector):
    source_name: str
    calls: list = field(default_factory=list)

    def collect(self, request: CollectionRequest) -> CollectionResult:
        self.calls.append(request.machine.vm_id)
        outcome = PatchOutcome(status="Failed") if self.source_name == "azure_control_plane" else None
        return CollectionResult(events=[], outcome=outcome)


def _machine(name: str, os_family: OSFamily) -> MachineIdentity:
    return MachineIdentity(
        vm_id=f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}",
        vm_name=name, resource_group="rg", subscription_id="s", os_family=os_family,
    )


def test_guest_windows_skipped_for_linux_machines():
    linux_machine = _machine("vm-linux", OSFamily.LINUX)
    control_plane = RecordingCollector(source_name="azure_control_plane")
    guest_windows = RecordingCollector(source_name="guest_windows")
    guest_linux = RecordingCollector(source_name="guest_linux")

    collectors = {
        Source.AZURE_CONTROL_PLANE: control_plane,
        Source.GUEST_WINDOWS: guest_windows,
        Source.GUEST_LINUX: guest_linux,
    }
    now = datetime.now(timezone.utc)
    collect_all("run-1", [linux_machine], collectors, now, now)

    assert guest_windows.calls == []
    assert guest_linux.calls == [linux_machine.vm_id]
    assert control_plane.calls == [linux_machine.vm_id]


def test_guest_linux_skipped_for_windows_machines():
    windows_machine = _machine("vm-win", OSFamily.WINDOWS)
    guest_windows = RecordingCollector(source_name="guest_windows")
    guest_linux = RecordingCollector(source_name="guest_linux")

    collectors = {Source.GUEST_WINDOWS: guest_windows, Source.GUEST_LINUX: guest_linux}
    now = datetime.now(timezone.utc)
    collect_all("run-1", [windows_machine], collectors, now, now)

    assert guest_linux.calls == []
    assert guest_windows.calls == [windows_machine.vm_id]


def test_datadog_and_control_plane_run_regardless_of_os():
    for os_family in (OSFamily.LINUX, OSFamily.WINDOWS, OSFamily.UNKNOWN):
        machine = _machine(f"vm-{os_family.value}", os_family)
        datadog = RecordingCollector(source_name="datadog")
        collectors = {Source.DATADOG_METRIC: datadog}
        now = datetime.now(timezone.utc)
        collect_all("run-1", [machine], collectors, now, now)
        assert datadog.calls == [machine.vm_id]


@dataclass
class _FixedResultCollector(Collector):
    source_name: str
    result: CollectionResult

    def collect(self, request: CollectionRequest) -> CollectionResult:
        return self.result


@dataclass
class _ExplodingCollector(Collector):
    source_name: str

    def collect(self, request: CollectionRequest) -> CollectionResult:
        raise RuntimeError("Run Command failed: simulated transport error")


def test_recollect_targeted_returns_the_full_per_source_result_not_just_events():
    """Found 2026-10-19: a bare flattened events list is exactly what let a
    recollection pass's real findings (checks_finding_counts/checks_
    performed/patch_extension_status) silently never reach save_machine_
    outcomes() - normalize.py::merge_recollection needs the whole
    CollectionResult shape per source, not only its events."""
    machine = _machine("vm-linux", OSFamily.LINUX)
    fixed_result = CollectionResult(
        events=[TimelineEvent(ts=datetime.now(timezone.utc), source=Source.GUEST_LINUX, kind="disk_usage",
                               summary="disk nearly full", raw_ref="guest:disk:vm-linux:0")],
        checks_performed=["disk usage"],
        checks_finding_counts={"disk usage": 1},
    )
    collectors = {Source.GUEST_LINUX: _FixedResultCollector(source_name="guest_linux", result=fixed_result)}
    now = datetime.now(timezone.utc)

    results = recollect_targeted("run-1", machine, ["disk usage"], collectors, now, now)

    assert results == {Source.GUEST_LINUX: fixed_result}


def test_recollect_targeted_skips_sources_that_dont_apply_to_this_machines_os():
    windows_machine = _machine("vm-win", OSFamily.WINDOWS)
    collectors = {
        Source.GUEST_LINUX: _FixedResultCollector(source_name="guest_linux", result=CollectionResult(events=[])),
        Source.GUEST_WINDOWS: _FixedResultCollector(source_name="guest_windows", result=CollectionResult(events=[])),
    }
    now = datetime.now(timezone.utc)

    results = recollect_targeted("run-1", windows_machine, [], collectors, now, now)

    assert Source.GUEST_LINUX not in results
    assert Source.GUEST_WINDOWS in results


def test_recollect_targeted_turns_a_collector_exception_into_a_collection_result_with_an_error():
    """Mirrors collect_all()'s own collect_one() behavior exactly - a
    crashing collector must still produce an entry (so merge_recollection
    can record a fresh collection_gaps note for it) rather than silently
    vanishing from the results dict, which would leave the ORIGINAL
    (possibly stale) gap text in place forever."""
    machine = _machine("vm-linux", OSFamily.LINUX)
    collectors = {Source.GUEST_LINUX: _ExplodingCollector(source_name="guest_linux")}
    now = datetime.now(timezone.utc)

    results = recollect_targeted("run-1", machine, ["disk usage"], collectors, now, now)

    assert results[Source.GUEST_LINUX].events == []
    assert "simulated transport error" in results[Source.GUEST_LINUX].error
