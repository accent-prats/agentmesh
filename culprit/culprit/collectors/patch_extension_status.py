"""Parses the Azure patch extension's own status file - the structured,
authoritative account of what the extension that Azure Update Manager
actually invokes did and why, as opposed to inferring a cause from OS
package-manager log lines (collectors/guest_linux.py's/guest_windows.py's
own log parsers).

Shared by both guest collectors because the schema is OS-agnostic: every
Azure VM extension (Linux and Windows alike) writes the same handler
status-reporting JSON shape, documented in the Azure/azure-linux-extensions
repo's design doc (docs/design-details.md, "Reporting Status and
Heartbeat") - that doc describes the extension *handler protocol* the guest
agent itself implements, not anything Linux-specific. Confirmed for the
Windows Patch Extension's on-disk location specifically via Microsoft's own
Update Manager troubleshooting docs (learn.microsoft.com/azure/update-
manager/troubleshoot) and a community-posted real status file at
`C:\\Packages\\Plugins\\Microsoft.CPlat.Core.WindowsPatchExtension\\<version>\\
Status\\<seq>.status` - Culprit has not independently verified this against
a live Windows box (the user's own proposal was validated on Linux only),
so treat the Windows path/schema as a documented, cited assumption rather
than something Culprit has confirmed first-hand.

Status file shape (one element array):
    [{"version": "1.0", "timestampUTC": "...",
      "status": {"name": ..., "operation": ..., "status": "success"|"error"|
                 "transitioning"|"warning", "code": 0,
                 "formattedMessage": {"lang": "en-US", "message": "..."},
                 "substatus": [{"name": ..., "status": ..., "code": ...,
                                "formattedMessage": {"message": "..."}}]}}]
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from culprit.models.evidence import Source, TimelineEvent

# Found 2026-10-18 by the same audit that caught azure_control_plane.py's
# identical bug: the extension's own `formattedMessage.message` can carry
# the same kind of hResult-code/troubleshooting-link text Azure's Resource
# Graph error.details[] does (both come from the same underlying patch
# subsystem), and 240 chars was silently cutting it off in the one place
# that reaches the LLM (TimelineEvent.summary - the un-truncated message
# only survives in `findings`, which only reporting/UI code ever reads,
# never rca_agent.py). Raised to match azure_control_plane.py's
# _PATCH_ERROR_SUMMARY_MAX_CHARS for the same reason: this is inherently
# low-cardinality (one top-level status event plus at most a handful of
# anomalous substatus entries per machine, not hundreds of short lines),
# so raising the per-event cap doesn't reopen the Activity Log token-bloat
# problem fixed earlier this session.
_SUMMARY_MAX_CHARS = 600
# Both scripts emit this exact string regardless of whether the extension
# directory or just the status file inside it was missing - one marker,
# not two, covers everything either script can actually produce.
_NO_STATUS_FILE_MARKER = "no status file found"

# Shared by guest_linux.py's waagent.log/core.log parsers and
# guest_windows.py's WindowsPatchExtension.log parser (found 2026-10-16:
# neither file ever collected the extension's own detailed operational
# log, only its terse .status summary parsed above - Microsoft's own
# Update Manager troubleshooting docs name these log files specifically
# as where "information about patches assessed/installed and problems
# encountered" actually lives). Deliberately a generic anomaly-keyword
# scan, not a schema-specific parse like parse_dpkg_log/parse_cbs_log
# get: unlike dpkg.log/CBS.log, Culprit has no live-verified real sample
# of waagent.log/core.log/WindowsPatchExtension.log line formats to build
# an exact regex against - same honesty this module's own docstring
# already applies to the Windows status-file path being "a documented,
# cited assumption" rather than independently confirmed.
EXTENSION_LOG_ANOMALY_RE = re.compile(
    r"error|exception|failed|timed? ?out|traceback|could not|refused|denied|unreachable",
    re.IGNORECASE,
)

# Found in review 2026-10-16: a routine, healthy summary line reporting a
# zero count ("0 packages failed", "No errors encountered") matches
# EXTENSION_LOG_ANOMALY_RE just as readily as a real failure does - the
# keyword alone can't distinguish "this failed" from "nothing failed".
# Checked alongside it (not merged into one regex, so each stays
# independently readable/testable) to suppress exactly that shape of
# false positive without narrowing the anomaly scan itself.
EXTENSION_LOG_ZERO_COUNT_RE = re.compile(
    r"\b0\s+\w*\s*(failed|denied|errors?|exceptions?)\b|\bno\s+(errors?|failures?|exceptions?|issues?)\b",
    re.IGNORECASE,
)

# Shared cap for every generic anomaly-keyword-scan parser in
# guest_linux.py/guest_windows.py (waagent.log, core.log, the extension
# wrapper log, VM Agent status, yum/dnf logs, journal/kernel errors,
# System Event Log). Found 2026-10-18 answering a direct "will this bloat
# LLM token usage" question: each anomaly event becomes one line in the
# RCA prompt via EvidenceBundle.render_timeline_text(), so a single
# genuinely noisy log file could otherwise add an unbounded number of
# prompt lines. 5 is generous for what these scans exist to catch (a
# handful of real failures, not a full log dump) while bounding the
# worst case.
MAX_ANOMALY_EVENTS_PER_SECTION = 5


def has_extension_log_anomaly(line: str) -> bool:
    """True if `line` contains a real anomaly - not just a healthy
    zero-count phrase. Found in a second review, 2026-10-16: checking
    "does the line contain an anomaly keyword AND not contain a
    zero-count phrase" (the original shape of this guard) suppresses the
    *entire line* whenever a zero-count phrase appears anywhere on it -
    including a line that also reports a real, separate failure, e.g.
    "0 packages failed to assess, but 2 packages failed to install:
    KB1, KB2" was silently dropped in full, the genuine failure lost
    along with the healthy phrase. Stripping only the zero-count
    substrings out first, then re-checking for an anomaly keyword in
    what's left, correctly keeps a line that has both and only drops a
    line that's purely a healthy zero-count summary."""
    if not EXTENSION_LOG_ANOMALY_RE.search(line):
        return False
    remainder = EXTENSION_LOG_ZERO_COUNT_RE.sub("", line)
    return bool(EXTENSION_LOG_ANOMALY_RE.search(remainder))

# Shared by the same three new parsers as EXTENSION_LOG_ANOMALY_RE above -
# same caveat applies: these are the formats Azure's own agent/extension
# logging is documented/commonly observed to use
# ("YYYY/MM/DD HH:MM:SS" for waagent.log, "YYYY-MM-DD HH:MM:SS,ffffff" for
# core.log's Python-logging output), not independently verified against a
# live sample. Best-effort only - a line that doesn't match any of these
# falls back to collection time (the caller's job, not this function's),
# the same graceful-degradation shape parse_dpkg_log already uses in
# guest_linux.py rather than this module inventing a different contract.
#
# Order matters: the two 23-char formats must come BEFORE the 19-char plain
# format - found 2026-10-18 while adding the WindowsUpdate.log entry, a
# real bug caught by its own new test: `line[:19]` of a WindowsUpdate.log
# line ("2026-10-16 03:04:00:456...") already parses cleanly as the plain
# 19-char format, so trying that one first would silently discard the
# fractional-second precision rather than ever reaching the more specific
# 23-char entry below it.
_LEADING_TIMESTAMP_FORMATS = (
    (19, "%Y/%m/%d %H:%M:%S"),      # waagent.log, e.g. "2026/10/16 03:04:00"
    (23, "%Y-%m-%d %H:%M:%S,%f"),   # core.log (Python logging default), e.g. "2026-10-16 03:04:00,000"
    (23, "%Y-%m-%d %H:%M:%S:%f"),   # WindowsUpdate.log (ETW-decoded), e.g. "2026-10-16 03:04:00:456"
    (19, "%Y-%m-%d %H:%M:%S"),      # WindowsPatchExtension.log / a plain ISO-ish prefix / CBS.log (the
                                     # comma+level text after the 19-char timestamp is just a separator,
                                     # not part of the format, so this same entry covers both)
)


def parse_leading_timestamp(line: str) -> datetime | None:
    """The real per-line timestamp if this line starts with one of the
    formats above, else None (caller falls back to collection time)."""
    for length, fmt in _LEADING_TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(line[:length], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# Found 2026-10-18 from a real user-shared RCA: a VM's actual failure (Oct
# 16) produced zero guest-side evidence in a scan run two days later (Oct
# 18), despite the guest Run Command completing successfully. Every guest
# log parser in guest_windows.py/guest_linux.py scans whatever text the
# fixed `-Tail 200`/`tail -n 200` happened to return, with no regard for
# whether those specific lines actually fall inside the collection window
# (`CollectionRequest.window_start`/`window_end`) the RCA is investigating -
# on a VM busy enough (this one had 7 deployment attempts in 30 days), two
# days of subsequent log volume can push the relevant lines out of the
# tail entirely, and conversely an unrelated OLD line still sitting in the
# tail can get wrongly flagged as relevant to a totally different, more
# recent window. `within_window()` is the shared filter every time-series
# log parser below now applies to each candidate event before keeping it.
def within_window(
    ts: datetime | None, window_start: datetime | None, window_end: datetime | None,
    end_buffer: timedelta = timedelta(hours=1),
) -> bool:
    """True when `ts` falls inside `[window_start, window_end + end_buffer]`.

    `window_start`/`window_end` being None means "no window given" (e.g. a
    caller/test that doesn't care about windowing) - always True in that
    case, preserving every parser's existing behavior when called without
    window arguments. `ts=None` (a line whose own timestamp couldn't be
    extracted) is also always True - fail OPEN rather than silently
    dropping a real anomaly because of an unfamiliar timestamp format,
    which would be worse than occasionally keeping an unrelated line the
    anomaly-keyword scan would otherwise have caught anyway. `end_buffer`
    accounts for collection happening slightly after `window_end` was
    computed (clock skew between the pipeline and the guest VM, plus the
    time the Run Command itself takes to execute and the script to run)."""
    if window_start is None or window_end is None or ts is None:
        return True
    return window_start <= ts <= window_end + end_buffer


def _message(status_obj: dict) -> str:
    formatted = status_obj.get("formattedMessage")
    if not isinstance(formatted, dict):
        return "(no message)"
    return (formatted.get("message") or "").strip() or "(no message)"


def _finding(
    source: Source, extension_name: str, extension_version: str | None,
    operation: str | None, status: str, code, message: str,
    substatus_name: str | None, raw_status_json: str | None,
) -> dict:
    return {
        "source": source.value,
        "extension_name": extension_name,
        "extension_version": extension_version,
        "operation": operation,
        "status": status,
        "code": code,
        "message": message,
        "substatus_name": substatus_name,
        "raw_status_json": raw_status_json,
    }


def parse_patch_extension_status(
    raw_text: str, vm_id: str, source: Source, extension_version: str | None = None,
) -> tuple[list[TimelineEvent], list[dict]]:
    """`extension_version` must come from the caller (the extension
    directory's own name on disk, e.g. "Microsoft.CPlat.Core.
    LinuxPatchExtension-1.6.71") - NOT from the status file's own
    top-level "version" field. That field is the status-reporting
    *protocol* version (always "1.0" per the schema this module's own
    docstring cites), not the installed extension's package version;
    reading it as if it were the latter was a real bug caught in review -
    it would have shown "v1.0" for every finding, on every machine,
    forever, instead of the actual installed version."""
    text = (raw_text or "").strip()
    if not text or text.lower() == _NO_STATUS_FILE_MARKER:
        return [], []

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        event = TimelineEvent(
            ts=datetime.now(timezone.utc), source=source, kind="patch_extension_status",
            summary="Patch extension status file found but was not valid JSON",
            detail={"parse_error": True},
            raw_ref=f"guest:ext_status:{vm_id}:0",
        )
        return [event], []

    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return [], []

    top = data[0].get("status") or {}
    extension_name = top.get("name") or "(unknown extension)"
    operation = top.get("operation")

    events: list[TimelineEvent] = []
    findings: list[dict] = []
    ref_index = 0

    def emit(status: str, code, message: str, substatus_name: str | None) -> None:
        nonlocal ref_index
        findings.append(_finding(
            source, extension_name, extension_version, operation, status, code, message,
            substatus_name, raw_status_json=text if not findings else None,
        ))
        events.append(TimelineEvent(
            ts=datetime.now(timezone.utc), source=source, kind="patch_extension_status",
            summary=(f"{extension_name} [{substatus_name}]: {message}" if substatus_name else f"{extension_name}: {message}")[:_SUMMARY_MAX_CHARS],
            detail={
                "extension_status": status, "extension_code": code,
                "operation": operation, "substatus_name": substatus_name,
                "anomaly": status in ("error", "warning"),
            },
            raw_ref=f"guest:ext_status:{vm_id}:{ref_index}",
        ))
        ref_index += 1

    # The top-level status is always surfaced, success or not - a success
    # here while Azure's own control-plane record says Failed is itself a
    # diagnostic fact (a reporting/communication gap, not a patch failure).
    emit(top.get("status") or "unknown", top.get("code"), _message(top), substatus_name=None)

    for sub in top.get("substatus") or []:
        if not isinstance(sub, dict):
            continue
        sub_status = sub.get("status") or "unknown"
        if sub_status not in ("error", "warning"):
            continue  # only anomalies - a fleet's worth of "success" substatus entries is noise, not evidence
        emit(sub_status, sub.get("code"), _message(sub), substatus_name=sub.get("name") or "(unnamed step)")

    return events, findings
