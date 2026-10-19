"""Invokes the allow-listed disk-cleanup scripts (scripts.py) via Azure Run
Command - the one place in this package that actually talks to Azure.

Mirrors culprit/collectors/guest_linux.py's/guest_windows.py's exact proven
pattern (cached ComputeManagementClient per subscription behind a lock,
begin_run_command + poller.result(timeout=60), a blanket except around the
whole call+poll) rather than inventing a new one - the only material
difference is this module's script can mutate guest state, so every call
site above this module (routes_remediation.py) gates entry far more
strictly than any read-only collector ever needs to.

The mount/drive to target is passed as a Run Command *parameter*, never
interpolated into the script string - that is what keeps the "script text
is fixed and reviewed, nothing caller-supplied becomes code" guarantee
intact even though the target path comes from stored diagnosis data, not a
constant.
"""
from __future__ import annotations

import logging
import threading
import time

from culprit.models.evidence import OSFamily
from culprit.remediation.scripts import (
    ALLOWED_LINUX_CLEANUP_SCRIPT,
    ALLOWED_WINDOWS_CLEANUP_SCRIPT,
    RESULT_MARKER,
    parse_remediation_result,
)

log = logging.getLogger(__name__)

try:  # pragma: no cover
    from azure.core.exceptions import ResourceExistsError
except ImportError:  # pragma: no cover
    class ResourceExistsError(Exception):
        """See the matching class/comment in guest_windows.py - same
        fallback, same reasoning (a separate try/except so a successfully-
        imported real ResourceExistsError never gets shadowed by this
        dummy one if azure-mgmt-compute/azure-identity are missing but
        azure-core itself is present)."""

try:  # pragma: no cover
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute.models import RunCommandInput, RunCommandInputParameter

    _COMPUTE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _COMPUTE_SDK_AVAILABLE = False

# Found 2026-10-18 by the review of the matching collector fix (guest_
# windows.py/guest_linux.py): this module has the exact same un-retried
# single-attempt Run Command bug - a VM with Azure Update Manager's own
# patch extension still running would fail disk-cleanup remediation with
# ResourceExistsError (HTTP 409, "another Run Command execution is already
# in progress") on the very first attempt, even though that condition
# resolves itself once the other execution finishes. Same fix, same
# constants - see guest_windows.py's own comment for the full story.
_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS = 15
_RUN_COMMAND_TIMEOUT_SECONDS = 60

# Defense in depth: `mount` ultimately comes from stored diagnosis data
# (RemediationPlaybook.automation_params), not a live, untrusted caller -
# but it's cheap insurance against it ever containing shell metacharacters,
# given it's handed to Azure as a command parameter either way.
_SAFE_MOUNT_RE = __import__("re").compile(r"^[A-Za-z0-9_/.:\\-]+$")


class RemediationRunner:
    def __init__(self, credential=None):
        self._credential = credential
        self._clients: dict[str, "ComputeManagementClient"] = {}
        self._lock = threading.Lock()

    def _client_for(self, subscription_id: str):
        if not _COMPUTE_SDK_AVAILABLE:
            raise RuntimeError(
                "azure-mgmt-compute / azure-identity are not installed. "
                "pip install them to run real remediation actions."
            )
        with self._lock:
            if self._credential is None:
                self._credential = DefaultAzureCredential()
            if subscription_id not in self._clients:
                self._clients[subscription_id] = ComputeManagementClient(self._credential, subscription_id)
        return self._clients[subscription_id]

    def run_disk_cleanup(
        self, subscription_id: str, resource_group: str, vm_name: str, os_family: OSFamily, mount: str,
    ) -> dict:
        """Returns a dict shaped like {"status": "success"|"failed",
        "message": str, "free_bytes_after": int | None} - never raises;
        every failure mode (bad input, transport error, script-reported
        failure) is normalized into this same shape so the caller always
        has exactly one place to read the outcome from."""
        if not mount or not _SAFE_MOUNT_RE.match(mount):
            return {"status": "failed", "message": f"Refusing to target an unsafe mount value: {mount!r}", "free_bytes_after": None}

        if os_family == OSFamily.LINUX:
            command_id, script, param_name, default_mount = "RunShellScript", ALLOWED_LINUX_CLEANUP_SCRIPT, "mount", "/"
        elif os_family == OSFamily.WINDOWS:
            command_id, script, param_name, default_mount = "RunPowerShellScript", ALLOWED_WINDOWS_CLEANUP_SCRIPT, "Mount", "C:\\"
        else:
            return {"status": "failed", "message": f"No disk-cleanup script for os_family={os_family!r}", "free_bytes_after": None}

        try:
            client = self._client_for(subscription_id)
        except Exception as exc:  # noqa: BLE001 - e.g. the SDK not installed; same failure shape as any other Run Command failure
            return {"status": "failed", "message": f"Run Command failed: {exc}", "free_bytes_after": None}
        started = time.monotonic()
        deadline = started + _RUN_COMMAND_TIMEOUT_SECONDS
        while True:
            remaining = max(1, round(deadline - time.monotonic()))
            try:
                poller = client.virtual_machines.begin_run_command(
                    resource_group,
                    vm_name,
                    RunCommandInput(
                        command_id=command_id,
                        script=[script],
                        parameters=[RunCommandInputParameter(name=param_name, value=mount or default_mount)],
                    ),
                )
                result = poller.result(timeout=remaining)
                stdout = result.value[0].message if result.value else ""
                break
            except ResourceExistsError as exc:
                if deadline - time.monotonic() <= _RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS:
                    return {"status": "failed", "message": f"Run Command failed: {exc}", "free_bytes_after": None}
                time.sleep(_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS)
            except Exception as exc:  # noqa: BLE001 - mirrors guest_linux.py's own blanket transport-error handling
                return {"status": "failed", "message": f"Run Command failed: {exc}", "free_bytes_after": None}

        # Added 2026-10-19 - same reasoning as the matching fix in
        # guest_linux.py/guest_windows.py::collect(), found by review while
        # diagnosing a real production case where a Run Command completed
        # cleanly but the agent's own ---SECTION----style result marker was
        # entirely missing from stdout. This script writes its one
        # ---REMEDIATION_RESULT--- marker LAST specifically so it survives
        # Azure's ~4KB output-cap truncation (which keeps the tail), but
        # parse_remediation_result's own "no result block found" reason
        # can't by itself distinguish that cap being hit (a noisy early
        # step, e.g. apt-get autoremove/DISM output, ate the whole budget
        # before the result line) from the script crashing early - logs
        # only a byte count and whether the marker was found, never any
        # cleanup-script output content.
        log.info(
            "remediation: Run Command on %s returned %d byte(s) of output, result marker %s",
            vm_name, len(stdout.encode("utf-8", "surrogatepass")), "found" if RESULT_MARKER in stdout else "NOT FOUND",
        )
        parsed = parse_remediation_result(stdout)
        if parsed["status"] == "success":
            return {
                "status": "success",
                "message": f"Freed space on {parsed.get('mount', mount)} - {parsed.get('free_bytes_after', 0)} bytes free now.",
                "free_bytes_after": parsed.get("free_bytes_after"),
            }
        return {
            "status": "failed",
            "message": parsed.get("reason", "Cleanup script reported failure with no reason given."),
            "free_bytes_after": parsed.get("free_bytes_after"),
        }
