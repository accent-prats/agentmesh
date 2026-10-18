"""Linux guest-OS collector.

Runs a fixed, reviewed, read-only script via Azure Run Command
(`RunShellScript`) - never arbitrary execution. The allow-listed commands
below are the entire guest-side attack surface; extending them requires an
explicit code review, not a config change, which is the point.

Parsing functions are pure (text in, facts out) and unit-tested directly
in tests/test_guest_linux_parsers.py without needing a live VM - that's
what makes "accurate" verifiable here: the regexes match the real log
formats of dpkg, apt and yum/dnf, not an invented shape.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timezone

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector
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
        """See the matching class/comment in guest_windows.py - same
        fallback, same reasoning (a separate try/except so a successfully-
        imported real ResourceExistsError never gets shadowed by this
        dummy one if azure-mgmt-compute/azure-identity are missing but
        azure-core itself is present)."""

try:  # pragma: no cover
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute.models import RunCommandInput

    _COMPUTE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _COMPUTE_SDK_AVAILABLE = False


# Fixed, read-only, allow-listed script - a single string RunCommandInput
# executes directly via a shell (the same contract guest_windows.py's own
# plain PowerShell script relies on, "RunShellScript" needs no "bash -c"
# wrapper of its own). Found while adding the EXT_STATUS section below and
# verifying it by actually running the reconstructed script: the previous
# "bash -c '...'" wrapper was built via shlex.split() and then rejoined
# with plain spaces in collect() (`" ".join(ALLOWED_LINUX_SCRIPT)`) -
# shlex.split() discards the quote characters it used to tokenize, so the
# rejoined string lost its quoting entirely. That left "bash -c" consuming
# only the next bare word ("echo") as its command, with "---DPKG_LOG---"
# silently swallowed as bash -c's $0 and never printed - the very first
# section's own marker has never actually appeared in a real run. Every
# later section still printed correctly, since after that inner "bash -c
# echo" returned, the rest of the semicolon-separated commands ran directly
# in the outer shell Azure provides - this was a narrow miss, not a total
# break, which is exactly why it went unnoticed. Also fixes a second,
# independently-confirmed bug in the same line: the REPO_CHECK curl
# command's `-w` format was `%{{http_code}}` (doubled braces - curl's
# format syntax is `%{http_code}` single-braced; found by literally running
# it: curl rejected it as an unknown write-out variable).
#
# No write, no delete, no arbitrary argument interpolation - the allow-
# listed commands below are the entire guest-side attack surface; extending
# them requires an explicit code review, not a config change.
ALLOWED_LINUX_SCRIPT = (
    "echo ---DPKG_LOG---; tail -n 200 /var/log/dpkg.log 2>/dev/null; "
    "echo ---APT_HISTORY---; tail -n 200 /var/log/apt/history.log 2>/dev/null; "
    "echo ---YUM_LOG---; tail -n 200 /var/log/yum.log 2>/dev/null; "
    "echo ---DNF_LOG---; tail -n 200 /var/log/dnf.log 2>/dev/null; "
    "echo ---DISK_USAGE---; df -h --output=target,pcent,avail 2>/dev/null; "
    "echo ---LOCK_HOLDER---; fuser /var/lib/dpkg/lock-frontend 2>&1; "
    "echo ---REPO_CHECK---; timeout 5 curl -o /dev/null -s -w \"%{http_code}\\n\" http://archive.ubuntu.com 2>&1; "
    "echo ---KERNELS---; dpkg -l 'linux-image-*' 2>/dev/null | grep ^ii; uname -r; "
    "echo ---SUBMAN---; timeout 5 subscription-manager status 2>&1; "
    "echo ---WAAGENT_LOG---; tail -n 200 /var/log/waagent.log 2>/dev/null; "
    "echo ---EXT_CORE_LOG---; "
    "LATESTCORE=$(ls -t /var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/*.core.log 2>/dev/null | head -1); "
    "if [ -n \"$LATESTCORE\" ]; then tail -n 200 \"$LATESTCORE\"; fi; "
    "echo ---EXT_WRAPPER_LOG---; "
    "LATESTWRAPPER=$(ls -t /var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/*_Enable.ext.log "
    "/var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/*.ext.log 2>/dev/null | head -1); "
    "if [ -n \"$LATESTWRAPPER\" ]; then tail -n 200 \"$LATESTWRAPPER\"; fi; "
    "echo ---REPO_DIAGNOSTICS---; "
    "REPOHOST=$(grep -h -oE '^deb[[:space:]]+https?://[^/[:space:]]+' /etc/apt/sources.list "
    "/etc/apt/sources.list.d/*.list 2>/dev/null | head -1 | sed -E 's#^deb[[:space:]]+https?://##'); "
    "if [ -z \"$REPOHOST\" ]; then REPOHOST=$(grep -h -oE '^baseurl=https?://[^/[:space:]]+' "
    "/etc/yum.repos.d/*.repo 2>/dev/null | head -1 | sed -E 's#^baseurl=https?://##'); fi; "
    "if [ -z \"$REPOHOST\" ]; then REPOHOST=archive.ubuntu.com; fi; "
    "echo \"configured_host=$REPOHOST\"; "
    "echo \"http_proxy=$http_proxy\"; "
    "echo \"https_proxy=$https_proxy\"; "
    "getent hosts \"$REPOHOST\" >/dev/null 2>&1 && echo dns_resolved=yes || echo dns_resolved=no; "
    "timeout 5 curl -o /dev/null -s -w \"http_status=%{http_code}\\n\" \"http://$REPOHOST\" 2>/dev/null || echo http_status=unreachable; "
    "echo ---JOURNAL_REBOOT---; "
    "journalctl --list-boots 2>/dev/null | tail -5; "
    "journalctl -k -p err -n 100 2>/dev/null; "
    "EXTDIR=$(find /var/lib/waagent -maxdepth 1 -type d "
    "-name 'Microsoft.CPlat.Core.LinuxPatchExtension-*' 2>/dev/null | sort -V | tail -1); "
    "echo ---EXT_VERSION---; "
    "if [ -n \"$EXTDIR\" ]; then basename \"$EXTDIR\" | sed 's/^Microsoft\\.CPlat\\.Core\\.LinuxPatchExtension-//'; fi; "
    "echo ---EXT_STATUS---; "
    "LATEST=; "
    "if [ -n \"$EXTDIR\" ]; then LATEST=$(ls -t \"$EXTDIR\"/status/*.status 2>/dev/null | head -1); fi; "
    "if [ -n \"$LATEST\" ]; then head -c 8192 \"$LATEST\"; else echo 'No status file found'; fi"
)


# See the matching constant in guest_windows.py - same reasoning, same
# value, kept as a separate module-level constant (not shared) to match
# this codebase's existing guest_linux.py/guest_windows.py duplication
# convention rather than introducing a new shared module for one constant.
_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS = 15

# See the matching comment in guest_windows.py - same reasoning.
_FIRST_PASS_TIMEOUT_SECONDS = 60
_RECOLLECT_TIMEOUT_SECONDS = 180


class GuestLinuxCollector(Collector):
    source_name = "guest_linux"

    def __init__(self, credential=None):
        self._credential = credential
        self._clients: dict[str, "ComputeManagementClient"] = {}
        # collect_all() runs one collector instance across a ThreadPoolExecutor
        # (culprit/pipeline/collection.py) - found in review 2026-09-27: the
        # check-then-act on self._clients below was not atomic, so two
        # machines in the same subscription collected concurrently could
        # both miss the cache and each build a throwaway client. Not a
        # safety bug (dict writes are still atomic under the GIL), just a
        # wasted client build - a lock makes it actually cache once per run.
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
            # ComputeManagementClient is bound to one subscription id; cache
            # one per subscription actually seen instead of hardcoding a
            # placeholder (which would build every request URL against a
            # fake subscription).
            if subscription_id not in self._clients:
                self._clients[subscription_id] = ComputeManagementClient(self._credential, subscription_id)
        return self._clients[subscription_id]

    def collect(self, request: CollectionRequest) -> CollectionResult:
        client = self._client_for(request.machine.subscription_id)
        # See guest_windows.py::collect()'s identical comment - a
        # non-empty request.only is the deliberate recollect_targeted
        # second pass, worth a longer timeout than the first attempt's
        # identical 60s window that already wasn't enough once.
        timeout = _RECOLLECT_TIMEOUT_SECONDS if request.only else _FIRST_PASS_TIMEOUT_SECONDS
        log.info("guest_linux: running Run Command on %s (timeout=%ds)", request.machine.vm_name, timeout)
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
                    RunCommandInput(command_id="RunShellScript", script=[ALLOWED_LINUX_SCRIPT]),
                )
                result = poller.result(timeout=remaining)
                stdout = result.value[0].message if result.value else ""
                break
            except ResourceExistsError as exc:
                if deadline - time.monotonic() <= _RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS:
                    log.warning(
                        "guest_linux: Run Command on %s still conflicted with another execution in progress "
                        "after %d attempt(s) over %.1fs - giving up (%s)",
                        request.machine.vm_name, attempt, time.monotonic() - started, safe_exc_summary(exc),
                    )
                    return CollectionResult(events=[], error=f"Run Command failed: {exc}")
                log.info(
                    "guest_linux: Run Command on %s conflicted with another execution in progress "
                    "(attempt %d) - retrying in %ds",
                    request.machine.vm_name, attempt, _RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS,
                )
                time.sleep(_RUN_COMMAND_CONFLICT_RETRY_INTERVAL_SECONDS)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "guest_linux: Run Command on %s failed after %.1fs (%s)",
                    request.machine.vm_name, time.monotonic() - started, safe_exc_summary(exc),
                )
                return CollectionResult(events=[], error=f"Run Command failed: {exc}")
        log.info("guest_linux: Run Command on %s completed after %.1fs", request.machine.vm_name, time.monotonic() - started)

        events, patch_extension_status, checks_performed = parse_linux_output(
            stdout, vm_id=request.machine.vm_id, window_start=request.window_start, window_end=request.window_end,
        )
        return CollectionResult(events=events, patch_extension_status=patch_extension_status, checks_performed=checks_performed)


_SECTION_RE = re.compile(r"^---(\w+)---$")

# Shared by parse_lock_holder/_checks_performed below (found by review
# 2026-10-19) - recognizes a shell's own "command not found" text, which
# LOCK_HOLDER/SUBMAN can both surface in their section content since their
# commands merge stderr into stdout via `2>&1` (so the parser can read
# specific output text, not just success/failure). Matches both bash's
# "command not found" and dash/sh's "<prog>: not found" (and "sh: 1: foo:
# not found", which also embeds a line number - a real, demonstrated
# false-positive source for parse_lock_holder's own PID regex below).
_COMMAND_UNAVAILABLE_RE = re.compile(r"command not found|:\s*not found\b", re.IGNORECASE)


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


# dpkg.log line shape: "2026-06-19 02:14:07 status half-installed linux-image-5.15.0-91-generic:amd64 5.15.0-91.101"
_DPKG_LINE_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<action>\S+) (?P<rest>.*)$")
_NO_SPACE_RE = re.compile(r"no space left on device", re.IGNORECASE)
_GZIP_FAIL_RE = re.compile(r"gzip:.*stdout", re.IGNORECASE)


def parse_dpkg_log(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        m = _DPKG_LINE_RE.match(line)
        # Window check uses the raw parsed value (None when the line
        # doesn't match dpkg.log's own format at all) so a line we can't
        # date stays in-window rather than being wrongly rejected - see
        # within_window()'s own fail-open design.
        parsed_ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) if m else None
        if not within_window(parsed_ts, window_start, window_end):
            continue
        ts = parsed_ts or datetime.now(timezone.utc)
        is_space_failure = bool(_NO_SPACE_RE.search(line) or _GZIP_FAIL_RE.search(line))
        if is_space_failure or (m and m.group("action") in ("status",) and "half-installed" in line):
            events.append(
                TimelineEvent(
                    ts=ts,
                    source=Source.GUEST_LINUX,
                    kind="package_manager_log",
                    summary=line.strip()[:240],
                    detail={
                        "write_failure": is_space_failure,
                        "disk_low": is_space_failure,
                    },
                    raw_ref=f"guest:dpkg.log:{vm_id}:{i}",
                )
            )
    return events


# apt history line shape: "Unpacking linux-image-5.15.0-91-generic (5.15.0-91.101) ... Error: ..."
_APT_ERROR_RE = re.compile(r"^Error:\s*(?P<msg>.+)$", re.MULTILINE)


def parse_apt_history(text: str, vm_id: str) -> list[TimelineEvent]:
    """Deliberately NOT given the window_start/window_end filtering the
    other time-series parsers got 2026-10-18: this regex only captures the
    "Error: ..." line itself, with no reliable way to associate it with
    the enclosing block's own "Start-Date:"/"End-Date:" timestamp without
    a deeper restructure - same "no live-verified sample" caveat already
    applied elsewhere in this file, now extended to "no reliable per-match
    timestamp to filter by" rather than guessing one."""
    events: list[TimelineEvent] = []
    for i, m in enumerate(_APT_ERROR_RE.finditer(text)):
        msg = m.group("msg")
        events.append(
            TimelineEvent(
                ts=datetime.now(timezone.utc),
                source=Source.GUEST_LINUX,
                kind="package_manager_log",
                summary=f"apt/history.log Error: {msg}"[:240],
                detail={"write_failure": bool(_NO_SPACE_RE.search(msg))},
                raw_ref=f"guest:apt/history.log:{vm_id}:{i}",
            )
        )
    return events


# `df -h --output=target,pcent,avail` -> lines like "/boot          99%    3.2M"
_DF_LINE_RE = re.compile(r"^(?P<mount>\S+)\s+(?P<pcent>\d+)%\s+(?P<avail>\S+)$")


def parse_disk_usage(text: str, vm_id: str, threshold_pct: int = 90) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        m = _DF_LINE_RE.match(line.strip())
        if not m:
            continue
        pcent = int(m.group("pcent"))
        if pcent >= threshold_pct:
            events.append(
                TimelineEvent(
                    ts=datetime.now(timezone.utc),
                    source=Source.GUEST_LINUX,
                    kind="disk_usage",
                    summary=f"{m.group('mount')} at {pcent}% used, {m.group('avail')} free",
                    detail={"disk_low": True, "mount": m.group("mount")},
                    raw_ref=f"guest:df:{vm_id}:{i}",
                )
            )
    return events


def parse_lock_holder(text: str, vm_id: str) -> list[TimelineEvent]:
    text = text.strip()
    if not text or "Permission denied" in text:
        return []
    # Found by review 2026-10-19: fuser (psmisc) isn't guaranteed installed
    # on a minimal/container image, and dash/sh's own "not found" text
    # (e.g. "sh: 1: fuser: not found") embeds a line number - without this
    # guard, that digit was matched by the PID regex below and fabricated
    # a false "dpkg lock held by pid 1" anomaly on a VM where fuser simply
    # never ran at all.
    if _COMMAND_UNAVAILABLE_RE.search(text):
        return []
    # Found by review 2026-10-19: fuser (psmisc) isn't guaranteed installed
    # on a minimal/container image, and dash/sh's own "not found" text
    # (e.g. "sh: 1: fuser: not found") embeds a line number - without this
    # guard, that digit was matched by the PID regex below and fabricated
    # a false "dpkg lock held by pid 1" anomaly on a VM where fuser simply
    # never ran at all.
    pid_match = re.search(r"(\d+)", text)
    if not pid_match:
        return []
    return [
        TimelineEvent(
            ts=datetime.now(timezone.utc),
            source=Source.GUEST_LINUX,
            kind="lock_state",
            summary=f"dpkg lock held by pid {pid_match.group(1)}",
            detail={"lock_held": True, "lock_holder_pid": pid_match.group(1)},
            raw_ref=f"guest:fuser:{vm_id}",
        )
    ]


def parse_repo_check(text: str, vm_id: str) -> list[TimelineEvent]:
    text = text.strip()
    if not text or text == "200":
        return []
    return [
        TimelineEvent(
            ts=datetime.now(timezone.utc),
            source=Source.GUEST_LINUX,
            kind="repo_check",
            summary=f"Repository check returned '{text}', expected 200",
            detail={"repo_unreachable": True},
            raw_ref=f"guest:repo_check:{vm_id}",
        )
    ]


# Shared by the anomaly-keyword-scan parsers below (parse_waagent_log,
# parse_extension_core_log, parse_extension_wrapper_log, parse_journal_reboot) -
# see the matching _anomaly_scan in guest_windows.py for why this is one
# shared implementation rather than four near-identical copies.
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
                ts=ts, source=Source.GUEST_LINUX, kind=kind,
                summary=line.strip()[:240], detail={},
                raw_ref=f"{raw_ref_prefix}:{vm_id}:{i}",
            )
        )
    return events[:MAX_ANOMALY_EVENTS_PER_SECTION]


def parse_waagent_log(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    """Azure Linux Agent's own log - a generic anomaly-keyword scan, see
    has_extension_log_anomaly's own comment for why this isn't an
    exact-format parse like parse_dpkg_log above, and for why a healthy
    "0 packages failed"/"no errors" phrase is suppressed without also
    dropping a real, separate failure that happens to share the line."""
    return _anomaly_scan(text, vm_id, "waagent_log", "guest:waagent.log", window_start, window_end)


def parse_extension_core_log(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    """The Linux patch extension's own detailed operational log
    (/var/log/azure/Microsoft.CPlat.Core.LinuxPatchExtension/<seq>.core.log)
    - Microsoft's own docs describe this as containing "information about
    patches assessed/installed and problems encountered during the
    process", distinct from the terse .status summary
    patch_extension_status.py already parses. Same generic anomaly scan
    as parse_waagent_log above - see has_extension_log_anomaly."""
    return _anomaly_scan(text, vm_id, "extension_core_log", "guest:core.log", window_start, window_end)


def parse_extension_wrapper_log(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    """The extension *wrapper's* log (`*_Enable.ext.log`/`*.ext.log`) -
    whether Azure actually invoked the patch operation at all, distinct
    from parse_extension_core_log's "what happened once it ran." Same
    generic anomaly scan and the same honesty caveat as every other new
    guest-log parser added 2026-10-18 - no live-verified real sample of
    this file's line format."""
    return _anomaly_scan(text, vm_id, "extension_wrapper_log", "guest:ext_wrapper.log", window_start, window_end)


def parse_yum_log(text: str, vm_id: str) -> list[TimelineEvent]:
    """Found 2026-10-18: YUM_LOG was already being fetched from the VM
    (ALLOWED_LINUX_SCRIPT) but parse_linux_output never read it - the data
    arrived and was silently dropped on every RHEL/CentOS/Fedora machine.
    Generic anomaly scan, not an exact-format parse like parse_dpkg_log -
    same reasoning as parse_waagent_log: no live-verified sample of a real
    yum.log's line format to build an exact regex against. Deliberately NOT
    given the window_start/window_end filtering the other time-series
    parsers got the same day, for the same reason: no confirmed timestamp
    format to extract here either, so there's nothing reliable to filter
    by without guessing."""
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        if not line.strip() or not has_extension_log_anomaly(line):
            continue
        events.append(
            TimelineEvent(
                ts=datetime.now(timezone.utc),
                source=Source.GUEST_LINUX,
                kind="package_manager_log",
                summary=f"yum.log: {line.strip()}"[:240],
                detail={},
                raw_ref=f"guest:yum.log:{vm_id}:{i}",
            )
        )
    return events[:MAX_ANOMALY_EVENTS_PER_SECTION]


def parse_dnf_log(text: str, vm_id: str) -> list[TimelineEvent]:
    """Same bug and same fix as parse_yum_log above, for DNF_LOG - including
    the same deliberate exclusion from window filtering."""
    events: list[TimelineEvent] = []
    for i, line in enumerate(text.splitlines()):
        if not line.strip() or not has_extension_log_anomaly(line):
            continue
        events.append(
            TimelineEvent(
                ts=datetime.now(timezone.utc),
                source=Source.GUEST_LINUX,
                kind="package_manager_log",
                summary=f"dnf.log: {line.strip()}"[:240],
                detail={},
                raw_ref=f"guest:dnf.log:{vm_id}:{i}",
            )
        )
    return events[:MAX_ANOMALY_EVENTS_PER_SECTION]


def parse_repo_diagnostics(text: str, vm_id: str) -> list[TimelineEvent]:
    """REPO_DIAGNOSTICS probes the *actually configured* repo host (unlike
    REPO_CHECK's hardcoded archive.ubuntu.com, kept as-is alongside this -
    see its own docstring) for DNS resolution and HTTP reachability, plus
    proxy env vars for context. Anomaly-gated: only emits when something's
    actually wrong, not a routine "all fine" confirmation line every run -
    keeps this consistent with every other new parser's token-conscious
    design (no finding = no event = zero added prompt tokens)."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields.setdefault(key.strip(), value.strip())
    host = fields.get("configured_host", "")
    dns_resolved = fields.get("dns_resolved") == "yes"
    http_status = fields.get("http_status", "")
    http_ok = http_status.isdigit() and http_status.startswith(("2", "3"))
    if dns_resolved and http_ok:
        return []
    return [
        TimelineEvent(
            ts=datetime.now(timezone.utc),
            source=Source.GUEST_LINUX,
            kind="repo_diagnostics",
            summary=f"Repo diagnostics for {host or '(unknown host)'}: "
            f"dns_resolved={dns_resolved}, http_status={http_status or 'unreachable'}",
            detail={
                "configured_host": host,
                "dns_resolution_failed": not dns_resolved,
                "repo_unreachable": not http_ok,
                "http_proxy": fields.get("http_proxy", ""),
                "https_proxy": fields.get("https_proxy", ""),
            },
            raw_ref=f"guest:repo_diagnostics:{vm_id}",
        )
    ]


def parse_journal_reboot(
    text: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> list[TimelineEvent]:
    """journalctl --list-boots (surfaces a mid-window reboot) + recent
    kernel errors (-k -p err) - same generic anomaly-keyword scan as
    parse_waagent_log/parse_extension_core_log, for the same reason: no
    live-verified sample of a real VM's journal line formats."""
    return _anomaly_scan(text, vm_id, "journal_reboot", "guest:journal", window_start, window_end)


def parse_subscription_manager(text: str, vm_id: str) -> list[TimelineEvent]:
    if "Overall Status: Current" in text or not text.strip():
        return []
    if "Invalid" in text or "expired" in text.lower() or "Unknown" in text:
        return [
            TimelineEvent(
                ts=datetime.now(timezone.utc),
                source=Source.GUEST_LINUX,
                kind="entitlement_state",
                summary=f"subscription-manager status: {text.strip().splitlines()[0]}",
                detail={"entitlement_expired": True},
                raw_ref=f"guest:subman:{vm_id}",
            )
        ]
    return []


def _log_if_found(parser_name: str, events: list[TimelineEvent], vm_id: str) -> list[TimelineEvent]:
    """Found 2026-10-18: the existing per-collector tracing covers the
    whole Run Command call these sections ride inside, but not which
    specific new signal actually fired - useful when triaging a real run's
    container logs. Logs only when something was actually found (never a
    "found nothing" line per section per machine - that's 114 machines x
    several new sections of pure noise for the common healthy case)."""
    if events:
        log.info("guest_linux: %s found %d anomaly event(s) for %s", parser_name, len(events), vm_id)
    return events


# Found 2026-10-19: lets the RCA prompt and the UI tell "we checked this and
# it's healthy" apart from "we never checked it" - see the long comment on
# CollectionResult.checks_performed (collectors/base.py) for the full
# rationale (a real RCA cited a vague "evidence gap" about
# subscription-manager even though SUBMAN runs unconditionally every scan).
# Keyed by the exact ---SECTION--- marker _split_sections() slices stdout on,
# so "did this section's marker actually get printed this run" (genuinely
# attempted, regardless of what it found) is the single source of truth -
# not a second, independently-maintained list that could drift out of sync
# with ALLOWED_LINUX_SCRIPT. EXT_VERSION/KERNELS/EXT_STATUS are deliberately
# left out: they're context strings or already surfaced via
# patch_extension_status's own structured findings, not a "check" a user
# would plausibly wonder "was this looked at?" about.
_SECTION_CHECK_LABELS: dict[str, str] = {
    "DPKG_LOG": "dpkg package manager log",
    "APT_HISTORY": "apt install/upgrade history",
    "YUM_LOG": "yum package manager log",
    "DNF_LOG": "dnf package manager log",
    "DISK_USAGE": "disk usage",
    "LOCK_HOLDER": "dpkg lock holder",
    "REPO_CHECK": "package repository reachability (archive.ubuntu.com)",
    "REPO_DIAGNOSTICS": "configured package repository DNS/HTTP reachability",
    "SUBMAN": "subscription-manager (entitlement) status",
    "WAAGENT_LOG": "Azure Linux Agent log",
    "EXT_CORE_LOG": "patch extension core log",
    "EXT_WRAPPER_LOG": "patch extension wrapper log",
    "JOURNAL_REBOOT": "system journal / reboot and kernel error history",
}

# Found by review 2026-10-19 - a real, demonstrated gap in the fix above:
# marker presence alone isn't "genuinely attempted." LOCK_HOLDER (`fuser ...
# 2>&1`) and SUBMAN (`subscription-manager status 2>&1`) both merge stderr
# into their section's own content so their parsers can read specific
# output text - but neither parser recognizes a shell "command not found"
# as anything other than "no anomaly," so a VM simply missing the fuser
# binary (psmisc isn't always installed) or subscription-manager (any
# non-RHEL box - this script already runs unconditionally against every
# Linux distro) would silently claim "checked, healthy" for a tool that
# was never actually available to check anything - reintroducing, one
# layer down, the exact false-confidence problem checks_performed exists
# to prevent. Every other section either redirects its command's own
# stderr to /dev/null (so a missing binary just yields empty output, read
# as "checked, nothing found" - a softer, already-accepted ambiguity, not
# a false *positive* claim) or explicitly branches with `&&`/`||` so a
# failure reports as a real, correctly-labeled negative (REPO_DIAGNOSTICS).
# See `_COMMAND_UNAVAILABLE_RE` (module-level, shared with parse_lock_holder).


def _checks_performed(sections: dict[str, str]) -> list[str]:
    return [
        label for key, label in _SECTION_CHECK_LABELS.items()
        if key in sections and not _COMMAND_UNAVAILABLE_RE.search(sections[key])
    ]


def parse_linux_output(
    stdout: str, vm_id: str, window_start: datetime | None = None, window_end: datetime | None = None,
) -> tuple[list[TimelineEvent], list[dict], list[str]]:
    sections = _split_sections(stdout)
    events: list[TimelineEvent] = []
    events += parse_dpkg_log(sections.get("DPKG_LOG", ""), vm_id, window_start, window_end)
    events += parse_apt_history(sections.get("APT_HISTORY", ""), vm_id)
    events += _log_if_found("parse_yum_log", parse_yum_log(sections.get("YUM_LOG", ""), vm_id), vm_id)
    events += _log_if_found("parse_dnf_log", parse_dnf_log(sections.get("DNF_LOG", ""), vm_id), vm_id)
    events += parse_disk_usage(sections.get("DISK_USAGE", ""), vm_id)
    events += parse_lock_holder(sections.get("LOCK_HOLDER", ""), vm_id)
    events += parse_repo_check(sections.get("REPO_CHECK", ""), vm_id)
    events += _log_if_found("parse_repo_diagnostics", parse_repo_diagnostics(sections.get("REPO_DIAGNOSTICS", ""), vm_id), vm_id)
    events += parse_subscription_manager(sections.get("SUBMAN", ""), vm_id)
    events += parse_waagent_log(sections.get("WAAGENT_LOG", ""), vm_id, window_start, window_end)
    events += parse_extension_core_log(sections.get("EXT_CORE_LOG", ""), vm_id, window_start, window_end)
    events += _log_if_found(
        "parse_extension_wrapper_log",
        parse_extension_wrapper_log(sections.get("EXT_WRAPPER_LOG", ""), vm_id, window_start, window_end),
        vm_id,
    )
    events += _log_if_found(
        "parse_journal_reboot", parse_journal_reboot(sections.get("JOURNAL_REBOOT", ""), vm_id, window_start, window_end), vm_id
    )
    ext_events, ext_findings = parse_patch_extension_status(
        sections.get("EXT_STATUS", ""), vm_id, Source.GUEST_LINUX,
        extension_version=sections.get("EXT_VERSION", "").strip() or None,
    )
    events += ext_events
    return events, ext_findings, _checks_performed(sections)
