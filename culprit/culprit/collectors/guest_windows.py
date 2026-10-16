"""Windows guest-OS collector.

Runs a fixed, read-only PowerShell script via Azure Run Command
(`RunPowerShellScript`). Same allow-list discipline as guest_linux.py:
the script below is the entire attack surface, and it is read-only -
`Get-*` cmdlets and log tails only, no `Set-*`/`Remove-*`.
"""
from __future__ import annotations

import re
import threading
from datetime import datetime, timezone

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector
from culprit.collectors.patch_extension_status import (
    has_extension_log_anomaly,
    parse_leading_timestamp,
    parse_patch_extension_status,
)
from culprit.models.evidence import Source, TimelineEvent

try:  # pragma: no cover
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute.models import RunCommandInput

    _COMPUTE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _COMPUTE_SDK_AVAILABLE = False


ALLOWED_WINDOWS_SCRIPT = r"""
Write-Output "---WU_LOG---"
Get-Content "$env:windir\WindowsUpdate.log" -Tail 200 -ErrorAction SilentlyContinue
Write-Output "---CBS_LOG---"
Get-Content "$env:windir\Logs\CBS\CBS.log" -Tail 200 -ErrorAction SilentlyContinue
Write-Output "---PENDING_REBOOT---"
Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
Write-Output "---WUAUSERV---"
(Get-Service wuauserv -ErrorAction SilentlyContinue).Status
Write-Output "---DISK_USAGE---"
Get-PSDrive -PSProvider FileSystem | ForEach-Object { "$($_.Name) $($_.Free) $($_.Used)" }
Write-Output "---WSUS_TARGET---"
(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue).WUServer
$extRoot = "C:\Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension"
$latestVersionDir = Get-ChildItem -Path $extRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object { [version]$_.Name } -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Output "---EXT_VERSION---"
if ($latestVersionDir) { Write-Output $latestVersionDir.Name }
Write-Output "---EXT_LOG---"
if ($latestVersionDir) {
    $extLogPath = "C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\$($latestVersionDir.Name)\WindowsPatchExtension.log"
    Get-Content $extLogPath -Tail 200 -ErrorAction SilentlyContinue
}
Write-Output "---EXT_STATUS---"
$latestStatusFile = $null
if ($latestVersionDir) {
    $latestStatusFile = Get-ChildItem -Path (Join-Path $latestVersionDir.FullName "Status") -Filter "*.status" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if ($latestStatusFile) {
    $extStatusContent = Get-Content $latestStatusFile.FullName -Raw -ErrorAction SilentlyContinue
    if ($extStatusContent.Length -gt 8192) { $extStatusContent = $extStatusContent.Substring(0, 8192) }
    Write-Output $extStatusContent
} else {
    Write-Output "No status file found"
}
"""


class GuestWindowsCollector(Collector):
    source_name = "guest_windows"

    def __init__(self, credential=None):
        self._credential = credential
        self._clients: dict[str, "ComputeManagementClient"] = {}
        # See the matching comment in guest_linux.py's GuestLinuxCollector -
        # collect_all() runs this instance across a ThreadPoolExecutor, and
        # the check-then-act below wasn't atomic without this lock.
        self._lock = threading.Lock()

    def _client_for(self, subscription_id: str):
        if not _COMPUTE_SDK_AVAILABLE:
            raise RuntimeError(
                "azure-mgmt-compute / azure-identity are not installed. "
                "pip install them, or use the demo collector for offline runs."
            )
        with self._lock:
            if self._credential is None:
                self._credential = DefaultAzureCredential()
            if subscription_id not in self._clients:
                self._clients[subscription_id] = ComputeManagementClient(self._credential, subscription_id)
        return self._clients[subscription_id]

    def collect(self, request: CollectionRequest) -> CollectionResult:
        client = self._client_for(request.machine.subscription_id)
        # A non-empty request.only means pipeline/collection.py::
        # recollect_targeted built this request - the RCA agent already
        # found the first pass's evidence too thin, so this is the one
        # deliberate second attempt worth spending extra patience on,
        # rather than repeating the identical 60s window that already
        # wasn't enough once (found 2026-10-15: this was hardcoded to 60
        # regardless of pass, so a VM still busy/unresponsive at the end
        # of the first attempt's window just failed again the same way).
        timeout = 180 if request.only else 60
        try:
            poller = client.virtual_machines.begin_run_command(
                request.machine.resource_group,
                request.machine.vm_name,
                RunCommandInput(command_id="RunPowerShellScript", script=[ALLOWED_WINDOWS_SCRIPT]),
            )
            result = poller.result(timeout=timeout)
            stdout = result.value[0].message if result.value else ""
        except Exception as exc:  # noqa: BLE001
            return CollectionResult(events=[], error=f"Run Command failed: {exc}")

        events, patch_extension_status = parse_windows_output(stdout, vm_id=request.machine.vm_id)
        return CollectionResult(events=events, patch_extension_status=patch_extension_status)


_SECTION_RE = re.compile(r"^---(\w+)---$")


def _split_sections(stdout: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current = None
    for line in stdout.splitlines():
        m = _SECTION_RE.match(line.strip())
        if m:
            current = m.group(1)
            sections[current] = []
            continue
        if current:
            sections[current].append(line)
    return {k: "\n".join(v) for k, v in sections.items()}


# WindowsUpdate.log ETW-decoded line shape includes a hex result code, e.g.
# "... WARNING: WU client failed Searching for updates with error 0x80244022"
_WU_ERROR_RE = re.compile(r"error (0x[0-9a-fA-F]{8})")

# CBS.log corruption/failure markers.
_CBS_FAIL_RE = re.compile(r"(CBS_E_\w+|Failed to (?:CSI Transaction|resolve).*|corrupt)", re.IGNORECASE)


def parse_wu_log(text: str, vm_id: str) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        m = _WU_ERROR_RE.search(line)
        if not m:
            continue
        code = m.group(1).lower()
        events.append(
            TimelineEvent(
                ts=datetime.now(timezone.utc),
                source=Source.GUEST_WINDOWS,
                kind="wu_log",
                summary=line.strip()[:240],
                detail={
                    "normalized_error": code,
                    "disk_low": code == "0x80070070",
                    "repo_unreachable": code in ("0x8024401c", "0x80244022"),
                },
                raw_ref=f"guest:WindowsUpdate.log:{vm_id}:{i}",
            )
        )
    return events


def parse_cbs_log(text: str, vm_id: str) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        if _CBS_FAIL_RE.search(line):
            events.append(
                TimelineEvent(
                    ts=datetime.now(timezone.utc),
                    source=Source.GUEST_WINDOWS,
                    kind="cbs_log",
                    summary=line.strip()[:240],
                    detail={"write_failure": "space" in line.lower()},
                    raw_ref=f"guest:CBS.log:{vm_id}:{i}",
                )
            )
    return events


def parse_pending_reboot(text: str, vm_id: str) -> list[TimelineEvent]:
    if text.strip().lower() != "true":
        return []
    return [
        TimelineEvent(
            ts=datetime.now(timezone.utc),
            source=Source.GUEST_WINDOWS,
            kind="pending_reboot",
            summary="RebootPending key present under Component Based Servicing",
            detail={"pending_reboot": True},
            raw_ref=f"guest:reboot_pending:{vm_id}",
        )
    ]


def parse_wuauserv_state(text: str, vm_id: str) -> list[TimelineEvent]:
    state = text.strip()
    if not state or state.lower() == "running":
        return []
    return [
        TimelineEvent(
            ts=datetime.now(timezone.utc),
            source=Source.GUEST_WINDOWS,
            kind="agent_state",
            summary=f"wuauserv service is '{state}', expected Running",
            detail={"agent_stale": True},
            raw_ref=f"guest:wuauserv:{vm_id}",
        )
    ]


_PSDRIVE_LINE_RE = re.compile(r"^(?P<name>\w):?\s+(?P<free>\d+)\s+(?P<used>\d+)$")


def parse_disk_usage(text: str, vm_id: str, min_free_bytes: int = 250 * 1024 * 1024) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        m = _PSDRIVE_LINE_RE.match(line.strip())
        if not m:
            continue
        free = int(m.group("free"))
        if free < min_free_bytes:
            events.append(
                TimelineEvent(
                    ts=datetime.now(timezone.utc),
                    source=Source.GUEST_WINDOWS,
                    kind="disk_usage",
                    summary=f"Drive {m.group('name')}: has only {free // (1024 * 1024)}MB free",
                    detail={"disk_low": True, "mount": f"{m.group('name')}:"},
                    raw_ref=f"guest:psdrive:{vm_id}:{i}",
                )
            )
    return events


def parse_extension_log(text: str, vm_id: str) -> list[TimelineEvent]:
    """The Windows patch extension's own detailed operational log
    (C:\\WindowsAzure\\Logs\\Plugins\\Microsoft.CPlat.Core.
    WindowsPatchExtension\\<version>\\WindowsPatchExtension.log) -
    pipeline/installation_report.py::_guest_log_path already names this
    exact path as the human-facing hint, but no collector read it until
    now. Same generic anomaly scan as guest_linux.py's
    parse_waagent_log/parse_extension_core_log - see
    has_extension_log_anomaly's own comment for why this isn't an
    exact-format parse, and for why a healthy "0 packages failed"/"no
    errors" phrase is suppressed without also dropping a real, separate
    failure that happens to share the line."""
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        if not line.strip() or not has_extension_log_anomaly(line):
            continue
        events.append(
            TimelineEvent(
                ts=parse_leading_timestamp(line) or datetime.now(timezone.utc),
                source=Source.GUEST_WINDOWS,
                kind="extension_log",
                summary=line.strip()[:240],
                detail={},
                raw_ref=f"guest:WindowsPatchExtension.log:{vm_id}:{i}",
            )
        )
    return events


def parse_windows_output(stdout: str, vm_id: str) -> tuple[list[TimelineEvent], list[dict]]:
    sections = _split_sections(stdout)
    events: list[TimelineEvent] = []
    events += parse_wu_log(sections.get("WU_LOG", ""), vm_id)
    events += parse_cbs_log(sections.get("CBS_LOG", ""), vm_id)
    events += parse_pending_reboot(sections.get("PENDING_REBOOT", ""), vm_id)
    events += parse_wuauserv_state(sections.get("WUAUSERV", ""), vm_id)
    events += parse_disk_usage(sections.get("DISK_USAGE", ""), vm_id)
    events += parse_extension_log(sections.get("EXT_LOG", ""), vm_id)
    ext_events, ext_findings = parse_patch_extension_status(
        sections.get("EXT_STATUS", ""), vm_id, Source.GUEST_WINDOWS,
        extension_version=sections.get("EXT_VERSION", "").strip() or None,
    )
    events += ext_events
    return events, ext_findings
