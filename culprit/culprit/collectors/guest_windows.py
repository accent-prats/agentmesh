"""Windows guest-OS collector.

Runs a fixed, read-only PowerShell script via Azure Run Command
(`RunPowerShellScript`). Same allow-list discipline as guest_linux.py:
the script below is the entire attack surface, and it is read-only -
`Get-*` cmdlets and log tails only, no `Set-*`/`Remove-*`.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timezone

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector, GuestLogSource
from culprit.collectors.patch_extension_status import (
    MAX_ANOMALY_EVENTS_PER_SECTION,
    has_extension_log_anomaly,
    parse_leading_timestamp,
    parse_patch_extension_status,
    within_window,
)
from culprit.models.evidence import Source, TimelineEvent
from culprit.observability import safe_exc_summary

log = logging.getLogger(__name__)

try:  # pragma: no cover
    from azure.core.exceptions import ResourceExistsError
except ImportError:  # pragma: no cover
    class ResourceExistsError(Exception):
        """Fallback so `except ResourceExistsError` below stays valid even
        when azure-core itself isn't installed - collect() already raises
        before reaching that point in that case (_client_for), so this is
        never actually matched against a real exception, only kept
        importable. Deliberately a separate try/except from the one below:
        azure-core is almost always present even when the heavier
        azure-mgmt-compute/azure-identity packages aren't (it's a shared
        base dependency), and binding the real class here first - not
        inside that block's `except ImportError` - avoids silently
        shadowing a successfully-imported real ResourceExistsError with
        this dummy one."""

try:  # pragma: no cover
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute.models import RunCommandInput

    _COMPUTE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _COMPUTE_SDK_AVAILABLE = False


# Section ORDER and per-section size below were both reworked 2026-10-19
# for the same reason and in the same way as guest_linux.py's identical
# comment on its own ALLOWED_LINUX_SCRIPT - see that comment for the full
# root-cause writeup (a live production VM's combined Run Command output
# exceeded Azure's documented ~4KB `instanceView` output cap, which keeps
# the LAST bytes written, not the first, silently discarding everything
# before that point with no error). Every `-Tail 200`/`-MaxEvents 100`
# dropped to a much smaller window, and EXT_STATUS's own 8192-character
# cap (nearly double Azure's entire output budget by itself) dropped to
# 3072. Only WSUS_CONNECTIVITY (the Windows analogue of guest_linux.py's
# REPO_DIAGNOSTICS, confirmed real root-cause evidence in production)
# actually moves - from right after DISK_USAGE to right before the
# extension-evidence cluster - leaving EXT_VERSION/EXT_LOG/
# COMMAND_EXECUTION_LOG/EXT_STATUS in their EXACT original relative order.
#
# Found by review 2026-10-19: the FIRST pass at this reorder also
# reshuffled EXT_VERSION/EXT_LOG/COMMAND_EXECUTION_LOG's relative order and
# moved COMMAND_EXECUTION_LOG - explicitly named in this very comment as a
# section that should "sit last" - EARLIER than it was before this whole
# fix (rank 12/13 -> 10/13), the opposite of the intent. The single,
# deliberate change below is isolating exactly the one thing this fix
# needs (protecting WSUS_CONNECTIVITY) without touching anything already
# correctly positioned.
ALLOWED_WINDOWS_SCRIPT = r"""
Write-Output "---WU_LOG---"
Get-Content "$env:windir\WindowsUpdate.log" -Tail 20 -ErrorAction SilentlyContinue
Write-Output "---CBS_LOG---"
Get-Content "$env:windir\Logs\CBS\CBS.log" -Tail 20 -ErrorAction SilentlyContinue
Write-Output "---PENDING_REBOOT---"
Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
Write-Output "---WUAUSERV---"
(Get-Service wuauserv -ErrorAction SilentlyContinue).Status
Write-Output "---WU_HISTORY---"
try {
    $wuSession = New-Object -ComObject Microsoft.Update.Session
    $wuSearcher = $wuSession.CreateUpdateSearcher()
    $wuHistoryCount = $wuSearcher.GetTotalHistoryCount()
    if ($wuHistoryCount -gt 0) {
        $wuSearcher.QueryHistory(0, [Math]::Min($wuHistoryCount, 20)) | ForEach-Object {
            "$($_.Date.ToString('yyyy-MM-dd HH:mm:ss')) ResultCode=$($_.ResultCode) Title=$($_.Title)"
        }
    }
} catch {}
Write-Output "---DISK_USAGE---"
Get-PSDrive -PSProvider FileSystem | ForEach-Object { "$($_.Name) $($_.Free) $($_.Used)" }
Write-Output "---VMAGENT_STATUS---"
if (Test-Path "C:\WindowsAzure\Logs\AggregateStatus" -PathType Leaf) {
    Get-Content "C:\WindowsAzure\Logs\AggregateStatus" -Tail 20 -ErrorAction SilentlyContinue
} elseif (Test-Path "C:\WindowsAzure\Logs\AggregateStatus") {
    $aggStatusFile = Get-ChildItem "C:\WindowsAzure\Logs\AggregateStatus" -Filter *.json -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($aggStatusFile) { Get-Content $aggStatusFile.FullName -Tail 20 -ErrorAction SilentlyContinue }
}
Write-Output "---SYSTEM_EVENTLOG---"
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3; StartTime=(Get-Date).AddHours(-6)} -MaxEvents 20 -ErrorAction SilentlyContinue |
    ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) [$($_.LevelDisplayName)] Id=$($_.Id) $($_.Message)" }
Write-Output "---WSUS_CONNECTIVITY---"
$wsusServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue).WUServer
if ($wsusServer) {
    Write-Output "wsus_server=$wsusServer"
    try {
        $wsusServerUri = $wsusServer
        if ($wsusServerUri -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $wsusServerUri = "http://$wsusServerUri" }
        $wsusHost = ([System.Uri]$wsusServerUri).Host
    } catch { $wsusHost = $null }
} else {
    Write-Output "wsus_server="
    $wsusHost = "windowsupdate.microsoft.com"
}
if ($wsusHost) {
    $wsusDns = Resolve-DnsName $wsusHost -ErrorAction SilentlyContinue
    Write-Output "dns_resolved=$(if ($wsusDns) {'yes'} else {'no'})"
    $wsusTest = Test-NetConnection -ComputerName $wsusHost -Port 443 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    Write-Output "tcp_reachable=$(if ($wsusTest -and $wsusTest.TcpTestSucceeded) {'yes'} else {'no'})"
}
$extRoot = "C:\Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension"
$latestVersionDir = Get-ChildItem -Path $extRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object { [version]$_.Name } -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Output "---EXT_VERSION---"
if ($latestVersionDir) { Write-Output $latestVersionDir.Name }
Write-Output "---EXT_LOG---"
if ($latestVersionDir) {
    $extLogPath = "C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\$($latestVersionDir.Name)\WindowsPatchExtension.log"
    Get-Content $extLogPath -Tail 20 -ErrorAction SilentlyContinue
}
Write-Output "---COMMAND_EXECUTION_LOG---"
if ($latestVersionDir) {
    $cmdExecLogPath = "C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\$($latestVersionDir.Name)\CommandExecution.log"
    Get-Content $cmdExecLogPath -Tail 20 -ErrorAction SilentlyContinue
}
Write-Output "---EXT_STATUS---"
$latestStatusFile = $null
if ($latestVersionDir) {
    $latestStatusFile = Get-ChildItem -Path (Join-Path $latestVersionDir.FullName "Status") -Filter "*.status" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if ($latestStatusFile) {
    $extStatusContent = Get-Content $latestStatusFile.FullName -Raw -ErrorAction SilentlyContinue
    if ($extStatusContent.Length -gt 3072) { $extStatusContent = $extStatusContent.Substring(0, 3072) }
    Write-Output $extStatusContent
} else {
    Write-Output "No status file found"
}
"""


# How long to wait before retrying a Run Command that failed because
# another execution is already in progress on this VM (ResourceExistsError,
# HTTP 409) - a time-bound condition (Azure Update Manager's own patch
# extension still finishing up, or a prior invocation still running), not a
# real failure. Found 2026-10-18 from real production logs/screenshots:
# this conflict fired on effectively every Windows (and Linux) machine a
# fleet scan touched, always within under a second (the conflict check is
# synchronous - no poller is even created), and since nothing retried,
# EVERY guest-side log for those machines (CBS.log, WindowsUpdate.log, the
# patch extension's own log, the Windows Event Log, etc.) was silently
# missing from every RCA - the agent was left reasoning from the two Azure
# control-plane events alone, routinely landing on "Insufficient evidence
# for a confident root cause" and even citing evidence that doesn't exist
# in the collected timeline. Module-level so tests can shrink it.
_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS = 15

# The two timeouts below were inline literals until the retry loop above
# needed tests to shrink the whole collection window (not just the retry
# interval) to keep a "retries until it finally gives up" test from taking
# a real ~60s - behavior is unchanged (still 60/180 by default).
_FIRST_PASS_TIMEOUT_SECONDS = 60
_RECOLLECT_TIMEOUT_SECONDS = 180


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
        timeout = _RECOLLECT_TIMEOUT_SECONDS if request.only else _FIRST_PASS_TIMEOUT_SECONDS
        log.info("guest_windows: running Run Command on %s (timeout=%ds)", request.machine.vm_name, timeout)
        started = time.monotonic()
        deadline = started + timeout
        attempt = 0
        while True:
            attempt += 1
            remaining = max(1, round(deadline - time.monotonic()))
            try:
                poller = client.virtual_machines.begin_run_command(
                    request.machine.resource_group,
                    request.machine.vm_name,
                    RunCommandInput(command_id="RunPowerShellScript", script=[ALLOWED_WINDOWS_SCRIPT]),
                )
                result = poller.result(timeout=remaining)
                stdout = result.value[0].message if result.value else ""
                break
            except ResourceExistsError as exc:
                if deadline - time.monotonic() <= _RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS:
                    log.warning(
                        "guest_windows: Run Command on %s still conflicted with another execution in progress "
                        "after %d attempt(s) over %.1fs - giving up (%s)",
                        request.machine.vm_name, attempt, time.monotonic() - started, safe_exc_summary(exc),
                    )
                    return CollectionResult(events=[], error=f"Run Command failed: {exc}")
                log.info(
                    "guest_windows: Run Command on %s conflicted with another execution in progress "
                    "(attempt %d) - retrying in %ds",
                    request.machine.vm_name, attempt, _RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS,
                )
                time.sleep(_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "guest_windows: Run Command on %s failed after %.1fs (%s)",
                    request.machine.vm_name, time.monotonic() - started, safe_exc_summary(exc),
                )
                return CollectionResult(events=[], error=f"Run Command failed: {exc}")
        log.info("guest_windows: Run Command on %s completed after %.1fs", request.machine.vm_name, time.monotonic() - started)
        # Added 2026-10-19 - see the identical comment in guest_linux.py's
        # collect(). A production Windows VM showed *every* tracked guest
        # section as "not collected" with no error, including DISK_USAGE
        # (which cannot legitimately be empty - every VM has a C: drive)
        # and WSUS_CONNECTIVITY/EXT_* near the end of the script (the
        # cluster the 2026-10-19 reorder was specifically meant to
        # protect). Without the raw byte count there was no way to tell
        # whether Azure's ~4KB output cap (see ALLOWED_WINDOWS_SCRIPT's
        # module comment) ate the whole output, or something else did -
        # Windows diagnostic text (CBS.log/WindowsUpdate.log lines, and
        # especially Get-WinEvent .Message text) runs far longer per
        # record than Linux's typically compact log lines, so even
        # -Tail 20/-MaxEvents 20 may not be enough per section. Logs only
        # a byte count and the recognized marker names (fixed labels,
        # never guest log content) - safe to leave on permanently.
        sections_found = sorted(_split_sections(stdout).keys())
        # len(stdout) would be Python's code-point length, not the encoded
        # byte length Azure's ~4KB cap actually measures - found by review
        # 2026-10-19: understates the real count for any non-ASCII content,
        # which is especially plausible here given this exact script reads
        # Get-WinEvent .Message text and other localized Windows log lines
        # - weakening the whole point of this line being an unambiguous
        # truncation signal.
        stdout_bytes = len(stdout.encode("utf-8", "surrogatepass"))
        log.info(
            "guest_windows: Run Command on %s returned %d byte(s) of output, recognized %d section marker(s): %s",
            request.machine.vm_name, stdout_bytes, len(sections_found), sections_found,
        )

        events, patch_extension_status, checks_performed, checks_unavailable, checks_finding_counts = parse_windows_output(
            stdout, vm_id=request.machine.vm_id, window_start=request.window_start, window_end=request.window_end,
        )
        return CollectionResult(
            events=events, patch_extension_status=patch_extension_status,
            checks_performed=checks_performed, checks_unavailable=checks_unavailable,
            checks_finding_counts=checks_finding_counts,
        )


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


def parse_wu_log(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        m = _WU_ERROR_RE.search(line)
        if not m:
            continue
        # Found 2026-10-18 alongside the window-filtering fix below: this
        # always stamped `datetime.now()` instead of the line's own real
        # timestamp (WindowsUpdate.log's ETW-decoded format, e.g.
        # "2026-10-16 03:04:00:456 ..." - now in parse_leading_timestamp's
        # format list) - harmless on its own, but it would have made
        # window filtering here meaningless (every line would always look
        # "now", i.e. always in-window). The window check below uses the
        # RAW parsed value (which can be None), never the `or now()`
        # fallback - checking the fallback would wrongly reject a line
        # just because its format wasn't recognized, defeating
        # within_window()'s own "ts=None stays in-window" design.
        parsed_ts = parse_leading_timestamp(line)
        if not within_window(parsed_ts, window_start, window_end):
            continue
        ts = parsed_ts or datetime.now(timezone.utc)
        code = m.group(1).lower()
        events.append(
            TimelineEvent(
                ts=ts,
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


def parse_cbs_log(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        if not _CBS_FAIL_RE.search(line):
            continue
        # Same fix as parse_wu_log above - CBS.log's own leading timestamp
        # ("2026-10-16 03:04:00, Error CBS ...") already matches an
        # existing parse_leading_timestamp format; this just wasn't using
        # it, always falling back to collection time. Window check uses the
        # raw parsed value (can be None -> stays in-window), not the
        # `or now()` fallback - see parse_wu_log's identical comment.
        parsed_ts = parse_leading_timestamp(line)
        if not within_window(parsed_ts, window_start, window_end):
            continue
        ts = parsed_ts or datetime.now(timezone.utc)
        events.append(
            TimelineEvent(
                ts=ts,
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


# Windows Update Agent's own IUpdateHistoryEntry.ResultCode enum
# (orcNotStarted=0, orcInProgress=1, orcSucceeded=2, orcSucceededWithErrors=3,
# orcFailed=4, orcAborted=5) - 3/4/5 are the "this update didn't cleanly
# install" outcomes worth surfacing.
_WU_HISTORY_LINE_RE = re.compile(r"^(?P<date>\S+ \S+) ResultCode=(?P<code>\d+) Title=(?P<title>.*)$")
_WU_HISTORY_FAILURE_CODES = {"3", "4", "5"}


def parse_wu_history(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    """The local Windows Update Agent's own install-history record
    (`(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().
    QueryHistory()`) - found 2026-10-18 auditing against the user-supplied
    "recommended evidence" spreadsheet: row 7's Windows column
    ("Windows Update records") is distinct from the separate WindowsUpdate.log
    trace file row (already collected as WU_LOG) - it's the structured
    per-update outcome record, the Windows analogue of Linux's dpkg/yum/dnf
    logs ("repository/package-specific download/install failures"). Only
    ResultCode values indicating a non-clean outcome are surfaced - a
    machine with a long, entirely successful update history would
    otherwise emit one event per line for no diagnostic value. No
    live-verified real sample of this API's exact Title/Date formatting -
    same honesty caveat already applied to this file's other new parsers."""
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        m = _WU_HISTORY_LINE_RE.match(line.strip())
        if not m or m.group("code") not in _WU_HISTORY_FAILURE_CODES:
            continue
        parsed_ts = parse_leading_timestamp(m.group("date"))
        if not within_window(parsed_ts, window_start, window_end):
            continue
        ts = parsed_ts or datetime.now(timezone.utc)
        events.append(
            TimelineEvent(
                ts=ts,
                source=Source.GUEST_WINDOWS,
                kind="wu_history",
                summary=f"Windows Update history: ResultCode={m.group('code')} for {m.group('title').strip()}"[:600],
                detail={"result_code": m.group("code")},
                raw_ref=f"guest:wu_history:{vm_id}:{i}",
            )
        )
    return events[:MAX_ANOMALY_EVENTS_PER_SECTION]


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


def parse_wsus_connectivity(text: str, vm_id: str) -> list[TimelineEvent]:
    """Replaces the old dead WSUS_TARGET section (fetched the WUServer
    registry value but never parsed it anywhere - found 2026-10-18) with a
    combined read + connectivity probe in one section, rather than two
    near-duplicate signals about the same topic. Falls back to the public
    Windows Update endpoint when no WSUS is configured.

    Anomaly-gated like guest_linux.py's parse_repo_diagnostics: only
    emits when there's a real problem. Also deliberately returns nothing
    when the probe simply didn't run (e.g. Resolve-DnsName/Test-NetConnection
    unavailable, or the registry value wasn't a parseable host) - the
    "no citation, no claim" discipline this codebase applies everywhere
    else applies here too: absence of data is not evidence of a problem,
    and manufacturing a false "unreachable" finding from a probe that
    never actually ran would be worse than reporting nothing."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields.setdefault(key.strip(), value.strip())
    if "dns_resolved" not in fields or "tcp_reachable" not in fields:
        return []
    wsus_server = fields.get("wsus_server", "")
    dns_resolved = fields["dns_resolved"] == "yes"
    tcp_reachable = fields["tcp_reachable"] == "yes"
    if dns_resolved and tcp_reachable:
        return []
    return [
        TimelineEvent(
            ts=datetime.now(timezone.utc),
            source=Source.GUEST_WINDOWS,
            kind="wsus_connectivity",
            summary=f"WSUS/Windows Update connectivity: server={wsus_server or '(public Windows Update)'}, "
            f"dns_resolved={dns_resolved}, tcp_reachable={tcp_reachable}",
            detail={
                "wsus_server": wsus_server or None,
                "dns_resolution_failed": not dns_resolved,
                "wsus_unreachable": not tcp_reachable,
            },
            raw_ref=f"guest:wsus_connectivity:{vm_id}",
        )
    ]


# Shared by the four anomaly-keyword-scan parsers below (parse_vmagent_status,
# parse_system_eventlog, parse_extension_log, parse_command_execution_log) -
# they were identical except for `kind`/`raw_ref` prefix, which made it easy
# for one to drift out of sync with the others (e.g. only some of them
# getting the window-filter fix). One shared implementation, one place to
# keep correct.
def _anomaly_scan(
    text: str, vm_id: str, kind: str, raw_ref_prefix: str,
    window_start: datetime | None, window_end: datetime | None,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        if not line.strip() or not has_extension_log_anomaly(line):
            continue
        # Window check uses the raw parsed value (can be None -> stays
        # in-window per within_window()'s own fail-open design) - checking
        # the `or now()` fallback instead would wrongly reject a line just
        # because its timestamp format wasn't recognized.
        parsed_ts = parse_leading_timestamp(line)
        if not within_window(parsed_ts, window_start, window_end):
            continue
        ts = parsed_ts or datetime.now(timezone.utc)
        events.append(
            TimelineEvent(
                ts=ts, source=Source.GUEST_WINDOWS, kind=kind,
                summary=line.strip()[:240], detail={},
                raw_ref=f"{raw_ref_prefix}:{vm_id}:{i}",
            )
        )
    return events[:MAX_ANOMALY_EVENTS_PER_SECTION]


def parse_vmagent_status(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    """The Azure VM Agent's own aggregate status
    (C:\\WindowsAzure\\Logs\\AggregateStatus) - Windows' counterpart to
    guest_linux.py's waagent.log, surfacing whether the agent itself
    received/triggered the extension request. Real on-disk shape (a single
    file vs. a directory of JSON snapshots) not independently verified -
    same honesty caveat as every other new guest-log parser added
    2026-10-18. Same generic anomaly-keyword scan, applied to the raw text
    regardless of whether it's JSON - a defensible-confidence choice over
    parsing specific JSON fields never confirmed against a real box."""
    return _anomaly_scan(text, vm_id, "vmagent_status", "guest:vmagent_status", window_start, window_end)


def parse_system_eventlog(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    """Windows System Event Log, Critical/Error/Warning levels, a fixed
    6-hour lookback (ALLOWED_WINDOWS_SCRIPT is static/non-parameterized by
    design - same constraint as every other section's fixed `-Tail 20`
    (shrunk from `-Tail 200` 2026-10-19 - see the module-level comment on
    ALLOWED_WINDOWS_SCRIPT), no real window_start can be interpolated into
    the script itself) -
    Windows' counterpart to guest_linux.py's parse_journal_reboot. Same
    generic anomaly-keyword scan and the same honesty caveat as every
    other new guest-log parser added 2026-10-18. Each line is
    independently scanned (a multi-line event's continuation lines carry
    no timestamp prefix and fall back to collection time, the same
    graceful degradation every other parser here already uses for a line
    it can't timestamp)."""
    return _anomaly_scan(text, vm_id, "system_eventlog", "guest:system_eventlog", window_start, window_end)


def parse_extension_log(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
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
    return _anomaly_scan(text, vm_id, "extension_log", "guest:WindowsPatchExtension.log", window_start, window_end)


def parse_command_execution_log(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    """The VM extension HANDLER's own wrapper log
    (C:\\WindowsAzure\\Logs\\Plugins\\Microsoft.CPlat.Core.
    WindowsPatchExtension\\<version>\\CommandExecution.log) - whether Azure
    actually invoked the patch operation at all, distinct from
    parse_extension_log's "what happened once it ran." Found 2026-10-18
    auditing against the user-supplied "recommended evidence" spreadsheet's
    row 7 (Windows column names this file specifically) - the Linux side's
    equivalent (parse_extension_wrapper_log) already existed, this one
    didn't. Same generic anomaly scan and the same honesty caveat as every
    other new guest-log parser added that day - no live-verified real
    sample of this file's line format."""
    return _anomaly_scan(text, vm_id, "extension_wrapper_log", "guest:CommandExecution.log", window_start, window_end)


def _log_if_found(parser_name: str, events: list[TimelineEvent], vm_id: str) -> list[TimelineEvent]:
    """See guest_linux.py's identical helper for why this exists and why
    it only logs on a non-empty result."""
    if events:
        log.info("guest_windows: %s found %d anomaly event(s) for %s", parser_name, len(events), vm_id)
    return events


# See guest_linux.py's identical GUEST_LOG_SOURCES for the full rationale
# and what each field means - one shared source of truth for the section
# label AND the raw_ref prefix the reporting layer's "logs used/not used"
# reconciliation (reporting/log_usage_view.py) keys off of. EXT_VERSION/
# EXT_STATUS are left out for the same reason as the Linux side.
GUEST_LOG_SOURCES: tuple[GuestLogSource, ...] = (
    GuestLogSource("WU_LOG", "Windows Update log", "guest:WindowsUpdate.log:"),
    GuestLogSource("CBS_LOG", "CBS (servicing) log", "guest:CBS.log:"),
    GuestLogSource("PENDING_REBOOT", "pending reboot registry key", "guest:reboot_pending:"),
    GuestLogSource("WUAUSERV", "Windows Update service (wuauserv) state", "guest:wuauserv:"),
    GuestLogSource("WU_HISTORY", "Windows Update install history", "guest:wu_history:"),
    GuestLogSource("DISK_USAGE", "disk usage", "guest:psdrive:"),
    GuestLogSource("WSUS_CONNECTIVITY", "WSUS/Windows Update connectivity", "guest:wsus_connectivity:"),
    GuestLogSource("VMAGENT_STATUS", "Azure VM Agent aggregate status", "guest:vmagent_status:"),
    GuestLogSource("SYSTEM_EVENTLOG", "Windows System Event Log", "guest:system_eventlog:"),
    GuestLogSource("EXT_LOG", "patch extension log", "guest:WindowsPatchExtension.log:"),
    GuestLogSource("COMMAND_EXECUTION_LOG", "patch extension command execution log", "guest:CommandExecution.log:"),
)


def _checks_performed(sections: dict[str, str]) -> list[str]:
    return [src.label for src in GUEST_LOG_SOURCES if src.section in sections]


# Every PowerShell cmdlet in ALLOWED_WINDOWS_SCRIPT already uses
# -ErrorAction SilentlyContinue (unlike guest_linux.py's ad hoc `2>&1`
# merges) - confirmed by review 2026-10-19 specifically for this reason -
# so no raw "cmdlet not found"-style text ever leaks into a section's own
# content here. This always returns [] today; kept as its own function
# (not just a bare `[]` at the call site) so a future Windows section that
# DOES need this guard has an obvious, matching place to add it, and so
# parse_windows_output's return shape stays structurally identical to
# parse_linux_output's.
def _checks_unavailable(sections: dict[str, str]) -> list[str]:
    return []


# See guest_linux.py's identical _track/finding_counts for why this exists:
# a label's "used" status must come from the true, uncapped per-section
# count recorded right here, never re-derived later from the persisted
# timeline (capped at _MAX_PERSISTED_TIMELINE_EVENTS - db/repository.py::
# save_machine_outcomes), which could silently evict a genuine finding.
def _track(counts: dict[str, int], section: str, events: list[TimelineEvent]) -> list[TimelineEvent]:
    counts[section] = counts.get(section, 0) + len(events)
    return events


def parse_windows_output(
    stdout: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> tuple[list[TimelineEvent], list[dict], list[str], list[str], dict[str, int]]:
    sections = _split_sections(stdout)
    section_counts: dict[str, int] = {}
    events: list[TimelineEvent] = []
    events += _track(section_counts, "WU_LOG", parse_wu_log(sections.get("WU_LOG", ""), vm_id, window_start, window_end))
    events += _track(section_counts, "CBS_LOG", parse_cbs_log(sections.get("CBS_LOG", ""), vm_id, window_start, window_end))
    events += _track(section_counts, "PENDING_REBOOT", parse_pending_reboot(sections.get("PENDING_REBOOT", ""), vm_id))
    events += _track(section_counts, "WUAUSERV", parse_wuauserv_state(sections.get("WUAUSERV", ""), vm_id))
    events += _track(
        section_counts, "WU_HISTORY",
        _log_if_found("parse_wu_history", parse_wu_history(sections.get("WU_HISTORY", ""), vm_id, window_start, window_end), vm_id),
    )
    events += _track(section_counts, "DISK_USAGE", parse_disk_usage(sections.get("DISK_USAGE", ""), vm_id))
    events += _track(
        section_counts, "WSUS_CONNECTIVITY",
        _log_if_found("parse_wsus_connectivity", parse_wsus_connectivity(sections.get("WSUS_CONNECTIVITY", ""), vm_id), vm_id),
    )
    events += _track(
        section_counts, "VMAGENT_STATUS",
        _log_if_found(
            "parse_vmagent_status", parse_vmagent_status(sections.get("VMAGENT_STATUS", ""), vm_id, window_start, window_end), vm_id
        ),
    )
    events += _track(
        section_counts, "SYSTEM_EVENTLOG",
        _log_if_found(
            "parse_system_eventlog", parse_system_eventlog(sections.get("SYSTEM_EVENTLOG", ""), vm_id, window_start, window_end), vm_id
        ),
    )
    events += _track(section_counts, "EXT_LOG", parse_extension_log(sections.get("EXT_LOG", ""), vm_id, window_start, window_end))
    events += _track(
        section_counts, "COMMAND_EXECUTION_LOG",
        _log_if_found(
            "parse_command_execution_log",
            parse_command_execution_log(sections.get("COMMAND_EXECUTION_LOG", ""), vm_id, window_start, window_end),
            vm_id,
        ),
    )
    ext_events, ext_findings = parse_patch_extension_status(
        sections.get("EXT_STATUS", ""), vm_id, Source.GUEST_WINDOWS,
        extension_version=sections.get("EXT_VERSION", "").strip() or None,
    )
    events += ext_events
    finding_counts = {
        src.label: section_counts[src.section] for src in GUEST_LOG_SOURCES if section_counts.get(src.section)
    }
    return events, ext_findings, _checks_performed(sections), _checks_unavailable(sections), finding_counts
