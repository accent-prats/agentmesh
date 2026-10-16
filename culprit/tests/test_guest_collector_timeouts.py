"""guest_windows.py/guest_linux.py::collect()'s Run Command timeout - had
zero test coverage of collect() itself before this (test_guest_windows_
parsers.py / test_guest_linux_parsers.py only cover the pure output
parsers). Covers the fix found 2026-10-15: both collectors hardcoded
`poller.result(timeout=60)` regardless of whether this was a fresh first
pass or pipeline/collection.py::recollect_targeted's deliberate second
attempt after the RCA agent already found the first pass's evidence too
thin (signaled by a non-empty request.only) - so a VM still busy/
unresponsive at the end of the first 60s window got retried under the
identical budget and very plausibly failed again the same way. Monkeypatches
_client_for directly (bypassing the real azure-mgmt-compute dependency
entirely) so this runs without the optional `culprit[azure]` extra
installed."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from culprit.collectors.base import CollectionRequest
from culprit.collectors.guest_linux import GuestLinuxCollector
from culprit.collectors.guest_windows import GuestWindowsCollector
from culprit.models.evidence import MachineIdentity, OSFamily


class _FakeRunCommandResult:
    def __init__(self, message=""):
        self.value = [type("MsgObj", (), {"message": message})()]


class _FakePoller:
    def __init__(self, recorder):
        self._recorder = recorder

    def result(self, timeout):
        self._recorder.append(timeout)
        return _FakeRunCommandResult()


class _FakeComputeClient:
    def __init__(self, recorder):
        self._recorder = recorder
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        return _FakePoller(self._recorder)


def _machine(os_family):
    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=os_family,
    )


@pytest.mark.parametrize("collector_cls,os_family", [
    (GuestWindowsCollector, OSFamily.WINDOWS),
    (GuestLinuxCollector, OSFamily.LINUX),
])
def test_first_pass_uses_the_original_60s_timeout(monkeypatch, collector_cls, os_family):
    recorder = []
    collector = collector_cls(credential=object())
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeComputeClient(recorder))
    # RunCommandInput only exists at module level when azure-mgmt-compute
    # is actually installed (guarded import) - neither collector's
    # collect() cares about its real shape, just that it's constructible.
    monkeypatch.setattr(
        __import__(collector_cls.__module__, fromlist=["RunCommandInput"]), "RunCommandInput", lambda **kw: kw, raising=False
    )

    request = CollectionRequest(
        machine=_machine(os_family), window_start=datetime.now(timezone.utc) - timedelta(hours=3),
        window_end=datetime.now(timezone.utc), run_id="run-1", only=[],
    )
    collector.collect(request)
    assert recorder == [60]


@pytest.mark.parametrize("collector_cls,os_family", [
    (GuestWindowsCollector, OSFamily.WINDOWS),
    (GuestLinuxCollector, OSFamily.LINUX),
])
def test_recollection_pass_gets_a_longer_timeout(monkeypatch, collector_cls, os_family):
    """A non-empty request.only is recollect_targeted's own signal that
    this is the deliberate second attempt - must not repeat the identical
    60s budget that already wasn't enough once."""
    recorder = []
    collector = collector_cls(credential=object())
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeComputeClient(recorder))
    monkeypatch.setattr(
        __import__(collector_cls.__module__, fromlist=["RunCommandInput"]), "RunCommandInput", lambda **kw: kw, raising=False
    )

    request = CollectionRequest(
        machine=_machine(os_family), window_start=datetime.now(timezone.utc) - timedelta(hours=3),
        window_end=datetime.now(timezone.utc), run_id="run-1",
        only=["guest_windows: Run Command timed out after 60s (WinRM unreachable)"],
    )
    collector.collect(request)
    assert recorder == [180]


class _FakeExplodingComputeClient:
    def __init__(self):
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        raise TimeoutError("WinRM unreachable")


@pytest.mark.parametrize("collector_cls,os_family,label", [
    (GuestWindowsCollector, OSFamily.WINDOWS, "guest_windows"),
    (GuestLinuxCollector, OSFamily.LINUX, "guest_linux"),
])
def test_a_failed_run_command_is_traced_but_still_returns_a_collection_gap(monkeypatch, caplog, collector_cls, os_family, label):
    """Found 2026-10-17: extended the same tracing discipline added to the
    RCA-provider path to Run Command too. Unlike that path, these
    collectors deliberately never re-raise - a single machine's collection
    failure must degrade to a collection_gaps entry, not crash the whole
    pipeline - so the property to pin here is "the warning is logged AND
    the existing error-conversion behavior is unchanged", not "re-raises"."""
    collector = collector_cls(credential=object())
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeExplodingComputeClient())
    monkeypatch.setattr(
        __import__(collector_cls.__module__, fromlist=["RunCommandInput"]), "RunCommandInput", lambda **kw: kw, raising=False
    )

    request = CollectionRequest(
        machine=_machine(os_family), window_start=datetime.now(timezone.utc) - timedelta(hours=3),
        window_end=datetime.now(timezone.utc), run_id="run-1", only=[],
    )

    with caplog.at_level("WARNING"):
        result = collector.collect(request)

    assert result.error == "Run Command failed: WinRM unreachable"  # unchanged behavior
    assert any(
        r.levelname == "WARNING" and f"{label}: Run Command on vm-1 failed" in r.message and "TimeoutError" in r.message
        for r in caplog.records
    )
