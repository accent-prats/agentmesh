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


class _FakeConflictingComputeClient:
    """Raises ResourceExistsError (Azure's "another Run Command execution
    is already in progress on this VM" 409) a fixed number of times, then
    succeeds - models the real production symptom (found 2026-10-18): the
    conflicting extension (Update Manager's own patch install, or a prior
    invocation) finishes eventually, so a retry within the existing
    timeout budget should recover rather than giving up on the very first
    attempt."""

    def __init__(self, recorder, fail_times):
        self._recorder = recorder
        self._fail_times = fail_times
        self._calls = 0
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        self._calls += 1
        self._recorder.append(self._calls)
        if self._calls <= self._fail_times:
            from azure.core.exceptions import ResourceExistsError

            raise ResourceExistsError("Run command extension execution is in progress.")
        return _FakePoller(self._recorder)


@pytest.mark.parametrize("collector_cls,os_family,label,module", [
    (GuestWindowsCollector, OSFamily.WINDOWS, "guest_windows", "culprit.collectors.guest_windows"),
    (GuestLinuxCollector, OSFamily.LINUX, "guest_linux", "culprit.collectors.guest_linux"),
])
def test_a_run_command_conflict_is_retried_and_recovers(monkeypatch, caplog, collector_cls, os_family, label, module):
    """The real bug: Run Command conflicts (409) were never retried, so
    every guest-side log (CBS.log, WindowsUpdate.log, the patch extension's
    own log, etc.) silently vanished from the RCA for any machine still
    running another Run Command when Culprit's own collection fired."""
    import importlib

    mod = importlib.import_module(module)
    monkeypatch.setattr(mod, "_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(mod, "_FIRST_PASS_TIMEOUT_SECONDS", 1)

    recorder = []
    collector = collector_cls(credential=object())
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeConflictingComputeClient(recorder, fail_times=2))
    monkeypatch.setattr(mod, "RunCommandInput", lambda **kw: kw, raising=False)

    request = CollectionRequest(
        machine=_machine(os_family), window_start=datetime.now(timezone.utc) - timedelta(hours=3),
        window_end=datetime.now(timezone.utc), run_id="run-1", only=[],
    )

    with caplog.at_level("INFO"):
        result = collector.collect(request)

    # _FakePoller.result() shares the same recorder (it logs the timeout it
    # was given) - so this is 3 begin_run_command call-counts (two
    # conflicts, then the successful third attempt) plus one trailing
    # poller.result() timeout from that successful attempt.
    assert recorder[:3] == [1, 2, 3]
    assert len(recorder) == 4
    assert result.error is None
    assert sum(
        1 for r in caplog.records
        if r.levelname == "INFO" and f"{label}: Run Command on vm-1 conflicted" in r.message
    ) == 2


@pytest.mark.parametrize("collector_cls,os_family,label,module", [
    (GuestWindowsCollector, OSFamily.WINDOWS, "guest_windows", "culprit.collectors.guest_windows"),
    (GuestLinuxCollector, OSFamily.LINUX, "guest_linux", "culprit.collectors.guest_linux"),
])
def test_a_persistent_run_command_conflict_eventually_gives_up(monkeypatch, caplog, collector_cls, os_family, label, module):
    """If the conflicting execution never finishes within the collection
    window, this must still degrade to a collection gap (not hang the
    pipeline forever) - same graceful-degradation contract as any other
    Run Command failure."""
    import importlib

    mod = importlib.import_module(module)
    monkeypatch.setattr(mod, "_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(mod, "_FIRST_PASS_TIMEOUT_SECONDS", 0.1)

    recorder = []
    collector = collector_cls(credential=object())
    # Always conflicts - fail_times larger than any plausible attempt count
    # within the tiny monkeypatched timeout below.
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeConflictingComputeClient(recorder, fail_times=10_000))
    monkeypatch.setattr(mod, "RunCommandInput", lambda **kw: kw, raising=False)

    request = CollectionRequest(
        machine=_machine(os_family), window_start=datetime.now(timezone.utc) - timedelta(hours=3),
        window_end=datetime.now(timezone.utc), run_id="run-1", only=[],
    )

    with caplog.at_level("WARNING"):
        result = collector.collect(request)

    assert "Run Command failed:" in result.error
    assert any(
        r.levelname == "WARNING" and f"{label}: Run Command on vm-1 still conflicted" in r.message
        for r in caplog.records
    )


def test_a_different_exception_type_is_not_retried_as_a_conflict(monkeypatch):
    """Only the specific 409 conflict is worth retrying - any other
    failure (auth, network, a real crash) must still fail immediately,
    exactly as before, rather than burning the collection window on
    retries that can't possibly succeed."""
    recorder = []
    collector = GuestWindowsCollector(credential=object())
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeExplodingComputeClient())
    monkeypatch.setattr(
        __import__(GuestWindowsCollector.__module__, fromlist=["RunCommandInput"]), "RunCommandInput", lambda **kw: kw, raising=False
    )

    request = CollectionRequest(
        machine=_machine(OSFamily.WINDOWS), window_start=datetime.now(timezone.utc) - timedelta(hours=3),
        window_end=datetime.now(timezone.utc), run_id="run-1", only=[],
    )

    result = collector.collect(request)
    assert result.error == "Run Command failed: WinRM unreachable"


# ── Window filtering wiring (found 2026-10-18): collect() must actually
# forward CollectionRequest's own window_start/window_end to the output
# parser, not just compute them for nothing - the real bug this guards
# against is a future refactor accidentally dropping the kwargs on the
# way from request to parser call. ─────────────────────────────────────

class _FakeWuLogPoller:
    """Returns a fixed stdout containing one WU_LOG anomaly timestamped
    2026-01-01 - whether collect() reports it depends entirely on whether
    the CollectionRequest's own window actually reaches the parser."""

    def result(self, timeout):
        return _FakeRunCommandResult(
            "---WU_LOG---\n"
            "2026-01-01 00:00:00:000  1  1 WU  WARNING: WU client failed Searching for updates with error 0x80244022\n"
        )


class _FakeWuLogComputeClient:
    def __init__(self):
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        return _FakeWuLogPoller()


def test_collect_forwards_the_requests_own_window_to_the_parser(monkeypatch):
    collector = GuestWindowsCollector(credential=object())
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeWuLogComputeClient())
    monkeypatch.setattr(
        __import__(GuestWindowsCollector.__module__, fromlist=["RunCommandInput"]), "RunCommandInput", lambda **kw: kw, raising=False
    )

    # A window nowhere near the fixture's 2026-01-01 timestamp - if collect()
    # actually threads request.window_start/window_end through to
    # parse_windows_output, the anomaly must be filtered out.
    out_of_window_request = CollectionRequest(
        machine=_machine(OSFamily.WINDOWS),
        window_start=datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc),
        run_id="run-1", only=[],
    )
    result = collector.collect(out_of_window_request)
    assert not any(e.kind == "wu_log" for e in result.events)

    in_window_request = CollectionRequest(
        machine=_machine(OSFamily.WINDOWS),
        window_start=datetime(2025, 12, 31, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 1, 1, 6, 0, tzinfo=timezone.utc),
        run_id="run-1", only=[],
    )
    result = collector.collect(in_window_request)
    assert any(e.kind == "wu_log" for e in result.events)


class _FakeDpkgLogPoller:
    """The Linux-side equivalent of _FakeWuLogPoller above - one dpkg.log
    anomaly timestamped 2026-01-01."""

    def result(self, timeout):
        return _FakeRunCommandResult(
            "---DPKG_LOG---\n2026-01-01 00:00:00 status half-installed linux-image-5.15.0-91-generic:amd64 5.15.0-91.101\n"
        )


class _FakeDpkgLogComputeClient:
    def __init__(self):
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        return _FakeDpkgLogPoller()


def test_collect_forwards_the_requests_own_window_to_the_parser_linux(monkeypatch):
    collector = GuestLinuxCollector(credential=object())
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeDpkgLogComputeClient())
    monkeypatch.setattr(
        __import__(GuestLinuxCollector.__module__, fromlist=["RunCommandInput"]), "RunCommandInput", lambda **kw: kw, raising=False
    )

    out_of_window_request = CollectionRequest(
        machine=_machine(OSFamily.LINUX),
        window_start=datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc),
        run_id="run-1", only=[],
    )
    result = collector.collect(out_of_window_request)
    assert not any(e.kind == "package_manager_log" for e in result.events)

    in_window_request = CollectionRequest(
        machine=_machine(OSFamily.LINUX),
        window_start=datetime(2025, 12, 31, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 1, 1, 6, 0, tzinfo=timezone.utc),
        run_id="run-1", only=[],
    )
    result = collector.collect(in_window_request)
    assert any(e.kind == "package_manager_log" for e in result.events)


@pytest.mark.parametrize("collector_cls,os_family,label", [
    (GuestWindowsCollector, OSFamily.WINDOWS, "guest_windows"),
    (GuestLinuxCollector, OSFamily.LINUX, "guest_linux"),
])
def test_collect_logs_output_byte_count_and_recognized_sections(monkeypatch, caplog, collector_cls, os_family, label):
    """Added 2026-10-19 after a real production Windows VM showed every
    tracked guest section as "not collected" with no error at all - there
    was no byte-level signal to tell truncation (Azure's ~4KB instanceView
    output cap, see ALLOWED_WINDOWS_SCRIPT/ALLOWED_LINUX_SCRIPT's module
    comments) apart from total collection failure or a parsing bug. Pins
    that collect() always logs the raw byte count plus which section
    markers survived, so the next occurrence is diagnosable from logs
    alone instead of re-litigated from UI screenshots."""
    recorder = []
    collector = collector_cls(credential=object())
    stdout = "---DISK_USAGE---\nC 1000 2000\n---SOME_OTHER_MARKER---\nignored\n"
    monkeypatch.setattr(collector, "_client_for", lambda sub_id: _FakeStdoutComputeClient(recorder, stdout))
    monkeypatch.setattr(
        __import__(collector_cls.__module__, fromlist=["RunCommandInput"]), "RunCommandInput", lambda **kw: kw, raising=False
    )

    request = CollectionRequest(
        machine=_machine(os_family), window_start=datetime.now(timezone.utc) - timedelta(hours=3),
        window_end=datetime.now(timezone.utc), run_id="run-1", only=[],
    )

    with caplog.at_level("INFO"):
        collector.collect(request)

    expected = f"{label}: Run Command on vm-1 returned {len(stdout)} byte(s) of output, recognized 2 section marker(s): ['DISK_USAGE', 'SOME_OTHER_MARKER']"
    assert any(r.levelname == "INFO" and expected in r.message for r in caplog.records)


class _FakeStdoutComputeClient:
    def __init__(self, recorder, stdout):
        self._recorder = recorder
        self._stdout = stdout
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        return _FakeStdoutPoller(self._recorder, self._stdout)


class _FakeStdoutPoller:
    def __init__(self, recorder, stdout):
        self._recorder = recorder
        self._stdout = stdout

    def result(self, timeout):
        self._recorder.append(timeout)
        return _FakeRunCommandResult(self._stdout)
