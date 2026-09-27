"""collect_all must not run guest_windows against a Linux machine or
guest_linux against a Windows one - wasted API calls that are guaranteed
to fail. Uses fake collectors that record whether they were invoked."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector
from culprit.models.evidence import MachineIdentity, OSFamily, PatchOutcome, Source
from culprit.pipeline.collection import collect_all


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
