"""Coverage for RemediationRunner.run_disk_cleanup's Run Command conflict
retry (found 2026-10-18 by an independent review of the matching fix in
guest_windows.py/guest_linux.py): this module had the exact same bug - a
single begin_run_command + poller.result() attempt with no retry, so a VM
with Azure Update Manager's own patch extension still running would fail
disk-cleanup remediation with ResourceExistsError (HTTP 409) immediately,
even though that condition resolves itself once the other execution
finishes. Monkeypatches _client_for directly (bypassing the real
azure-mgmt-compute dependency entirely), same style as
test_guest_collector_timeouts.py."""
from __future__ import annotations

import pytest

from culprit.models.evidence import OSFamily
from culprit.remediation import runner as runner_module
from culprit.remediation.runner import RemediationRunner


class _FakeRunCommandResult:
    def __init__(self, message=""):
        self.value = [type("MsgObj", (), {"message": message})()]


class _FakePoller:
    def __init__(self, recorder):
        self._recorder = recorder

    def result(self, timeout):
        self._recorder.append(("result", timeout))
        return _FakeRunCommandResult("---REMEDIATION_RESULT---\nstatus=success mount=/ free_bytes_after=1000\n")


class _FakeConflictingComputeClient:
    def __init__(self, recorder, fail_times):
        self._recorder = recorder
        self._fail_times = fail_times
        self._calls = 0
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        self._calls += 1
        self._recorder.append(("begin", self._calls))
        if self._calls <= self._fail_times:
            from azure.core.exceptions import ResourceExistsError

            raise ResourceExistsError("Run command extension execution is in progress.")
        return _FakePoller(self._recorder)


class _FakeExplodingComputeClient:
    def __init__(self):
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        raise TimeoutError("WinRM unreachable")


def _patch_run_command_input(monkeypatch):
    monkeypatch.setattr(runner_module, "RunCommandInput", lambda **kw: kw, raising=False)
    monkeypatch.setattr(runner_module, "RunCommandInputParameter", lambda **kw: kw, raising=False)


def test_a_run_command_conflict_is_retried_and_recovers(monkeypatch):
    monkeypatch.setattr(runner_module, "_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(runner_module, "_RUN_COMMAND_TIMEOUT_SECONDS", 1)
    _patch_run_command_input(monkeypatch)

    recorder = []
    runner = RemediationRunner(credential=object())
    monkeypatch.setattr(runner, "_client_for", lambda sub_id: _FakeConflictingComputeClient(recorder, fail_times=2))

    result = runner.run_disk_cleanup("sub-1", "rg", "vm-1", OSFamily.LINUX, mount="/")

    assert result["status"] == "success"
    assert [r for r in recorder if r[0] == "begin"] == [("begin", 1), ("begin", 2), ("begin", 3)]


def test_a_persistent_run_command_conflict_eventually_gives_up(monkeypatch):
    monkeypatch.setattr(runner_module, "_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(runner_module, "_RUN_COMMAND_TIMEOUT_SECONDS", 0.1)
    _patch_run_command_input(monkeypatch)

    runner = RemediationRunner(credential=object())
    monkeypatch.setattr(runner, "_client_for", lambda sub_id: _FakeConflictingComputeClient([], fail_times=10_000))

    result = runner.run_disk_cleanup("sub-1", "rg", "vm-1", OSFamily.LINUX, mount="/")

    assert result["status"] == "failed"
    assert "Run Command failed:" in result["message"]


def test_a_different_exception_type_is_not_retried_as_a_conflict(monkeypatch):
    _patch_run_command_input(monkeypatch)
    runner = RemediationRunner(credential=object())
    monkeypatch.setattr(runner, "_client_for", lambda sub_id: _FakeExplodingComputeClient())

    result = runner.run_disk_cleanup("sub-1", "rg", "vm-1", OSFamily.LINUX, mount="/")

    assert result == {"status": "failed", "message": "Run Command failed: WinRM unreachable", "free_bytes_after": None}


def test_client_acquisition_failure_still_returns_the_same_failure_shape(monkeypatch):
    """Preserves the pre-fix contract: run_disk_cleanup never raises, even
    when _client_for itself fails (e.g. the azure SDK isn't installed)."""
    _patch_run_command_input(monkeypatch)
    runner = RemediationRunner(credential=object())

    def _boom(sub_id):
        raise RuntimeError("azure-mgmt-compute / azure-identity are not installed.")

    monkeypatch.setattr(runner, "_client_for", _boom)

    result = runner.run_disk_cleanup("sub-1", "rg", "vm-1", OSFamily.LINUX, mount="/")

    assert result["status"] == "failed"
    assert "not installed" in result["message"]
    assert result["free_bytes_after"] is None


class _FakeStdoutPoller:
    def __init__(self, stdout):
        self._stdout = stdout

    def result(self, timeout):
        return _FakeRunCommandResult(self._stdout)


class _FakeStdoutComputeClient:
    def __init__(self, stdout):
        self._stdout = stdout
        self.virtual_machines = self

    def begin_run_command(self, resource_group, vm_name, run_command_input):
        return _FakeStdoutPoller(self._stdout)


def test_run_disk_cleanup_logs_output_byte_count_and_whether_the_result_marker_was_found(monkeypatch, caplog):
    """Added 2026-10-19 - same reasoning/pattern as the matching fix in
    guest_linux.py/guest_windows.py::collect() (found by review of that
    fix): this module's own Run Command call has the identical Azure
    output-cap exposure, and parse_remediation_result's "no result block
    found" reason alone can't tell "the cap ate the whole budget before
    the always-last RESULT_MARKER line" apart from "the script crashed
    early." Pins that run_disk_cleanup always logs the byte count (true
    encoded bytes, not code-point length - see the matching collector fix
    for why that distinction matters) plus whether the marker was found."""
    _patch_run_command_input(monkeypatch)
    runner = RemediationRunner(credential=object())
    stdout = "noisy cleanup output\n"  # no ---REMEDIATION_RESULT--- marker at all
    monkeypatch.setattr(runner, "_client_for", lambda sub_id: _FakeStdoutComputeClient(stdout))

    with caplog.at_level("INFO"):
        result = runner.run_disk_cleanup("sub-1", "rg", "vm-1", OSFamily.LINUX, mount="/")

    assert result["status"] == "failed"  # unchanged pre-existing behavior
    expected = f"remediation: Run Command on vm-1 returned {len(stdout.encode('utf-8'))} byte(s) of output, result marker NOT FOUND"
    assert any(r.levelname == "INFO" and expected in r.message for r in caplog.records)
