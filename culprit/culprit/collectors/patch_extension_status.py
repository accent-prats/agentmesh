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
from datetime import datetime, timezone

from culprit.models.evidence import Source, TimelineEvent

_SUMMARY_MAX_CHARS = 240
# Both scripts emit this exact string regardless of whether the extension
# directory or just the status file inside it was missing - one marker,
# not two, covers everything either script can actually produce.
_NO_STATUS_FILE_MARKER = "no status file found"


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
