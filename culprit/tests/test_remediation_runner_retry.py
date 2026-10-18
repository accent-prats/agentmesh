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
