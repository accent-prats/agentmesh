"""Azure control-plane collector: Resource Graph (patch outcomes) + Activity
Log (control-plane changes in the blast window).

Requires (proposal Section 12, security posture):
  - An Entra ID workload identity (a plain `DefaultAzureCredential` picks up
    a managed identity in production, or `az login` locally) with:
      * Reader on the subscription/resource group
      * The custom 'Culprit Reader' role for Resource Graph + Activity Log
        (see culprit/security/rbac/culprit-reader-role.json)
  - `azure-identity`, `azure-mgmt-resourcegraph`, `azure-mgmt-monitor`

This module is read-only by construction: every client call below is a
`list`/`resources` query. There is no code path here that can write to a
subscription, which is what makes the RBAC role's read-only scope an
enforceable guarantee rather than a policy on paper.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from pydantic import ValidationError

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector
from culprit.models.evidence import AzureApiErrorDetail, PatchOutcome, Source, TimelineEvent
from culprit.observability import safe_exc_summary

log = logging.getLogger(__name__)

# Deliberately higher than the 240-char convention every other TimelineEvent
# summary in this codebase uses (collectors/guest_linux.py, guest_windows.py,
# azure_monitor.py, datadog_collector.py) - found 2026-10-18 from a real
# production message that measured 456 chars: "Failed to assess and install
# update [...]. Reason: [..., result code=Failed, hResult:0x80070002. For
# information on diagnosing this error, see
# https://aka.ms/TroubleshootVMGuestPatching.]" - the 240-char cap was
# silently cutting this off mid-sentence, before the hResult code and before
# Azure's own troubleshooting-link/diagnostic guidance, which is exactly the
# kind of "does Update Manager suggest a fix" signal worth giving the RCA
# model (user-requested 2026-10-18). Safe to raise only for this one event
# type: `error.details[]` is itself a short, Azure-capped array (the real
# production UI showed "The latest 3 errors are shared in details") - a
# handful of long entries per machine, not hundreds of short ones, so this
# doesn't reopen the Activity Log token-bloat problem fixed earlier this
# session (azure_control_plane.py::_activity_log_events's own 20-event cap).
#
# Raised again the same day, 600 -> 900: a real top-level `error.message`
# (used by the fallback below when `error.details[]` is empty) measured 632
# chars on its own - longer than a single `details[]` entry, because the
# top-level field wraps the same diagnostic text in Azure's own boilerplate
# preamble ("1 errors reported. The latest N errors are shared in details.
# To view all errors, review this log file on the machine: [path]") before
# the actual "Failed to assess and install update... hResult:...aka.ms
# link" content. 600 was still cutting the link off for this real message;
# 900 gives real headroom without meaningfully changing the token-bloat
# argument above (still one event, not a growing count).
_PATCH_ERROR_SUMMARY_MAX_CHARS = 900

# Defense-in-depth found by review: both _INSTALL_RESULT_QUERY and
# _ASSESSMENT_RESULT_QUERY already `limit 1` (at most one install row and
# one assessment row per machine), but `_parse_error_details()`/
# `error_detail_messages` impose no length limit on `error.details[]`
# itself - the 600-char-per-event safety argument above rests on a real
# production UI screenshot showing Azure's own self-imposed "latest 3
# errors are shared in details" behavior, not an enforced API/schema
# limit. Mirrors `_MAX_ACTIVITY_LOG_EVENTS` (added this same session after
# a real 262-event/41K-char-prompt incident) rather than trusting observed
# behavior to hold for every tenant/error shape.
_MAX_PATCH_ERROR_EVENTS = 10

try:  # pragma: no cover - exercised only when the optional Azure SDKs are installed
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest

    _AZURE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _AZURE_SDK_AVAILABLE = False


# Real Resource Graph table/column shapes exposed by Azure Update Manager.
# `patchinstallationresources` carries per-run, per-machine install results;
# `patchassessmentresources` carries the last assessment (pending patch
# counts); `maintenanceresources` carries the maintenance run itself.
_INSTALL_RESULT_QUERY = """
patchinstallationresources
| where type =~ 'microsoft.compute/virtualmachines/patchinstallationresults'
| where id startswith '{vm_id}'
| where properties.startDateTime >= datetime('{window_start}')
| where properties.startDateTime <= datetime('{window_end}')
| project id, properties
| order by tostring(properties.startDateTime) desc
| limit 1
"""
# `properties` is Resource Graph's dynamic-typed column, so a bare
# `order by properties.startDateTime` fails every real invocation with
# "(InvalidQuery) ... order operator: key can't be of dynamic type" -
# `where`/comparison operators tolerate a dynamic operand, `order by`'s
# sort key does not. That exception was being caught by collect()'s own
# blanket except below and silently degrading every real machine's
# PatchOutcome to normalize.py's generic "Unknown" placeholder - found
# live, reported as "status is coming as unknown" on a real tenant run.
# Cast to a string, not datetime() - discovery.py's own
# _ALL_PATCH_RESULTS_QUERY already relies on the same fact (ISO-8601
# string lexical ordering matches chronological ordering) for its
# `arg_max`, so this matches an already-proven pattern rather than
# introducing a second cast convention.

# Found 2026-10-18 auditing against a user-supplied "recommended evidence"
# list: `patchassessmentresources` (missing/available patch counts, last
# assessment status) was never queried at all - only the install-result
# table above. Modeled byte-for-byte on _INSTALL_RESULT_QUERY (same
# vm_id/window filter shape, same tostring() cast for the same dynamic-
# column reason) - only the table name and `type` filter differ.
_ASSESSMENT_RESULT_QUERY = """
patchassessmentresources
| where type =~ 'microsoft.compute/virtualmachines/patchassessmentresults'
| where id startswith '{vm_id}'
| where properties.startDateTime >= datetime('{window_start}')
| where properties.startDateTime <= datetime('{window_end}')
| project id, properties
| order by tostring(properties.startDateTime) desc
| limit 1
"""

# See _activity_log_events()'s own comment for why this exists - bounds
# the worst case (a busy VM with hundreds of routine Activity Log rows)
# after the read/write filter already does most of the work.
_MAX_ACTIVITY_LOG_EVENTS = 20


class AzureControlPlaneCollector(Collector):
    source_name = "azure_control_plane"

    def __init__(self, subscription_id: str | None = None, credential=None):
        self.subscription_id = subscription_id
        # A pre-built credential (typically from culprit.collectors.azure_auth.build_credential,
        # fed by whatever's saved on the /culprit/settings screen) takes
        # priority; falling back to DefaultAzureCredential keeps the demo
        # and any caller that doesn't pass one working unchanged.
        self._credential = credential
        self._graph_client = None
        self._monitor_client = None

    def _ensure_clients(self, subscription_id: str) -> None:
        if not _AZURE_SDK_AVAILABLE:
            raise RuntimeError(
                "azure-identity / azure-mgmt-resourcegraph / azure-mgmt-monitor are not installed. "
                "pip install them, or use collectors.demo.DemoAzureControlPlaneCollector for offline runs."
            )
        if self._credential is None:
            self._credential = DefaultAzureCredential()
        if self._graph_client is None:
            self._graph_client = ResourceGraphClient(self._credential)
        if self._monitor_client is None:
            self._monitor_client = MonitorManagementClient(self._credential, subscription_id)

    def collect(self, request: CollectionRequest) -> CollectionResult:
        self._ensure_clients(request.machine.subscription_id)
        events: list[TimelineEvent] = []
        outcome: PatchOutcome | None = None
        error = None

        started = time.monotonic()
        try:
            from culprit.security.kql import escape_kql_string

            query = _INSTALL_RESULT_QUERY.format(
                vm_id=escape_kql_string(request.machine.vm_id),
                window_start=request.window_start.isoformat(),
                window_end=request.window_end.isoformat(),
            )
            result = self._graph_client.resources(
                QueryRequest(subscriptions=[request.machine.subscription_id], query=query)
            )
            rows = result.data or []
            log.info(
                "azure_control_plane: install-result query for %s returned %d row(s) after %.1fs",
                request.machine.vm_name, len(rows), time.monotonic() - started,
            )
            if rows:
                props = rows[0]["properties"]
                outcome = _outcome_from_install_result(props)
                events.append(
                    TimelineEvent(
                        ts=_parse_ts(props.get("lastModifiedDateTime") or props.get("startDateTime")),
                        source=Source.AZURE_CONTROL_PLANE,
                        kind="patch_result",
                        summary=f"patchinstallationresults -> {props.get('status')} / {props.get('errorCode') or ''}".strip(),
                        detail={"normalized_error": (props.get("errorCode") or "").lower()},
                        raw_ref=f"resourcegraph:{rows[0]['id']}",
                    )
                )
                # One event per Azure-reported error detail - the same
                # `ApiError.details[]` entries a separate internal report
                # was found pulling from this exact Resource Graph field
                # (2026-10-15) to show messages like "There is no enough
                # time left to continue applying the next update" that
                # Culprit's own RCA had no visibility into. Reaches the
                # model for free via render_timeline_text() - no prompt
                # change needed, same as patch_extension_status.py.
                if outcome.error_details:
                    for i, detail in enumerate(outcome.error_details[:_MAX_PATCH_ERROR_EVENTS]):
                        events.append(
                            TimelineEvent(
                                ts=_parse_ts(props.get("lastModifiedDateTime") or props.get("startDateTime")),
                                source=Source.AZURE_CONTROL_PLANE,
                                kind="azure_patch_error",
                                summary=(f"Azure-reported install error: {detail.message or detail.code or '(no message)'}")[
                                    :_PATCH_ERROR_SUMMARY_MAX_CHARS
                                ],
                                detail={"code": detail.code, "target": detail.target},
                                raw_ref=f"resourcegraph:{rows[0]['id']}:error:{i}",
                            )
                        )
                elif outcome.error_message:
                    # Found 2026-10-18 from a real production RCA that
                    # fabricated a wrong hResult code and a nonexistent
                    # "vendor documentation" citation: when `error.details[]`
                    # is empty, the only real diagnostic text Azure gave us
                    # (the full "Failed to assess and install update...
                    # hResult:0x...  For information on diagnosing this
                    # error, see https://aka.ms/..." message, confirmed
                    # directly against the real Azure Portal "Update
                    # deployment run" pane for this exact operation) lives
                    # entirely in the top-level `error.message` field - which
                    # previously never became a TimelineEvent at all. With
                    # nothing concrete to cite, the model invented a
                    # plausible-sounding but WRONG specific answer instead of
                    # admitting it lacked detail - a more dangerous variant
                    # of "no citation, no claim" than a fabricated raw_ref,
                    # since the cited event (bare patch_result) is real, just
                    # uninformative. Same cap/kind as the per-detail events
                    # above so this is indistinguishable downstream.
                    events.append(
                        TimelineEvent(
                            ts=_parse_ts(props.get("lastModifiedDateTime") or props.get("startDateTime")),
                            source=Source.AZURE_CONTROL_PLANE,
                            kind="azure_patch_error",
                            summary=f"Azure-reported install error: {outcome.error_message}"[:_PATCH_ERROR_SUMMARY_MAX_CHARS],
                            detail={},
                            raw_ref=f"resourcegraph:{rows[0]['id']}:error_message",
                        )
                    )
        except Exception as exc:  # noqa: BLE001 - collection must degrade, not crash the pipeline
            log.warning(
                "azure_control_plane: install-result query for %s failed after %.1fs (%s)",
                request.machine.vm_name, time.monotonic() - started, safe_exc_summary(exc),
            )
            error = f"Resource Graph query failed: {exc}"

        assessment_started = time.monotonic()
        try:
            from culprit.security.kql import escape_kql_string

            assessment_query = _ASSESSMENT_RESULT_QUERY.format(
                vm_id=escape_kql_string(request.machine.vm_id),
                window_start=request.window_start.isoformat(),
                window_end=request.window_end.isoformat(),
            )
            assessment_result = self._graph_client.resources(
                QueryRequest(subscriptions=[request.machine.subscription_id], query=assessment_query)
            )
            assessment_rows = assessment_result.data or []
            log.info(
                "azure_control_plane: assessment-result query for %s returned %d row(s) after %.1fs",
                request.machine.vm_name, len(assessment_rows), time.monotonic() - assessment_started,
            )
            if assessment_rows:
                assessment_props = assessment_rows[0]["properties"]
                summary_detail = _summarize_assessment_result(assessment_props)
                pending = sum(summary_detail["available_patch_counts"].values())
                summary_line = f"patchassessmentresults -> {summary_detail['status']}"
                if pending:
                    summary_line += f", {pending} patch(es) pending"
                if summary_detail["reboot_pending"]:
                    summary_line += ", reboot pending"
                events.append(
                    TimelineEvent(
                        ts=_parse_ts(assessment_props.get("lastModifiedDateTime") or assessment_props.get("startDateTime")),
                        source=Source.AZURE_CONTROL_PLANE,
                        kind="patch_assessment",
                        summary=summary_line,
                        detail=summary_detail,
                        raw_ref=f"resourcegraph:{assessment_rows[0]['id']}",
                    )
                )
                # Mirrors the azure_patch_error events above - until this,
                # `error_detail_messages` only ever landed in `detail`
                # (never sent to the LLM, see render_timeline_text()), so a
                # FAILED assessment's own Azure-reported reasons were
                # invisible to the RCA even though they were already being
                # collected. Found 2026-10-18 alongside the truncation fix
                # for the install-result side of this exact gap.
                error_detail_messages = summary_detail["error_detail_messages"]
                if error_detail_messages:
                    for i, message in enumerate(error_detail_messages[:_MAX_PATCH_ERROR_EVENTS]):
                        events.append(
                            TimelineEvent(
                                ts=_parse_ts(assessment_props.get("lastModifiedDateTime") or assessment_props.get("startDateTime")),
                                source=Source.AZURE_CONTROL_PLANE,
                                kind="azure_assessment_error",
                                summary=f"Azure-reported assessment error: {message}"[:_PATCH_ERROR_SUMMARY_MAX_CHARS],
                                raw_ref=f"resourcegraph:{assessment_rows[0]['id']}:error:{i}",
                            )
                        )
                elif summary_detail["error_message"]:
                    # Same install-result gap, mirrored: when
                    # error.details[] is empty, the only real content lives
                    # in the top-level error.message field.
                    events.append(
                        TimelineEvent(
                            ts=_parse_ts(assessment_props.get("lastModifiedDateTime") or assessment_props.get("startDateTime")),
                            source=Source.AZURE_CONTROL_PLANE,
                            kind="azure_assessment_error",
                            summary=f"Azure-reported assessment error: {summary_detail['error_message']}"[:_PATCH_ERROR_SUMMARY_MAX_CHARS],
                            raw_ref=f"resourcegraph:{assessment_rows[0]['id']}:error_message",
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "azure_control_plane: assessment-result query for %s failed after %.1fs (%s)",
                request.machine.vm_name, time.monotonic() - assessment_started, safe_exc_summary(exc),
            )
            error = (error + "; " if error else "") + f"Assessment query failed: {exc}"

        activity_started = time.monotonic()
        try:
            activity_events = self._activity_log_events(request)
            log.info(
                "azure_control_plane: activity-log query for %s returned %d event(s) after %.1fs",
                request.machine.vm_name, len(activity_events), time.monotonic() - activity_started,
            )
            events.extend(activity_events)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "azure_control_plane: activity-log query for %s failed after %.1fs (%s)",
                request.machine.vm_name, time.monotonic() - activity_started, safe_exc_summary(exc),
            )
            error = (error + "; " if error else "") + f"Activity Log query failed: {exc}"

        return CollectionResult(events=events, outcome=outcome, error=error)

    def _activity_log_events(self, request: CollectionRequest) -> list[TimelineEvent]:
        from culprit.security.kql import escape_kql_string

        filter_str = (
            f"eventTimestamp ge '{request.window_start.isoformat()}' "
            f"and eventTimestamp le '{request.window_end.isoformat()}' "
            f"and resourceUri eq '{escape_kql_string(request.machine.vm_id)}'"
        )
        raw_entries = list(self._monitor_client.activity_logs.list(filter=filter_str))
        # Found 2026-10-18 from a real production run: this used to build
        # one TimelineEvent per raw row with no cap - a single machine
        # returned 262 events in one run, and since render_timeline_text()
        # puts one line per event straight into the RCA prompt, that's
        # plausibly tens of thousands of characters of mostly routine,
        # read-only noise (a very likely contributor to a real OpenAI 400
        # over prompt size this session) drowning out the 1-2 lines that
        # actually matter. Azure's own operation-name convention is
        # `{provider}/{resourceType}/{operation}` where the last segment is
        # "read"/"write"/"action"/"delete" - keep anything that failed
        # (regardless of type, since even a failed read can matter, e.g. a
        # permission error) plus every non-read operation; drop routine
        # reads. Capped and sorted most-recent-first on top of that, since
        # even the filtered set could still be large on a busy VM.
        relevant = [
            entry for entry in raw_entries
            if (entry.status and entry.status.value == "Failed")
            or (entry.operation_name and entry.operation_name.value and not entry.operation_name.value.lower().endswith("/read"))
        ]
        relevant.sort(key=lambda e: e.event_timestamp or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        kept = relevant[:_MAX_ACTIVITY_LOG_EVENTS]
        if len(kept) < len(raw_entries):
            log.info(
                "azure_control_plane: activity log for %s had %d event(s), kept %d after filtering",
                request.machine.vm_name, len(raw_entries), len(kept),
            )

        events: list[TimelineEvent] = []
        for entry in kept:
            events.append(
                TimelineEvent(
                    ts=entry.event_timestamp or datetime.now(timezone.utc),
                    source=Source.AZURE_CONTROL_PLANE,
                    kind="activity_log",
                    summary=f"{entry.operation_name.localized_value if entry.operation_name else 'operation'} "
                    f"by {entry.caller or 'unknown'} -> {entry.status.value if entry.status else ''}",
                    detail={
                        "nsg_change": bool(entry.operation_name and "networkSecurityGroups" in (entry.operation_name.value or "")),
                        "policy_block": bool(entry.operation_name and "policy" in (entry.operation_name.value or "").lower() and entry.status and entry.status.value == "Failed"),
                    },
                    raw_ref=f"activitylog:{entry.event_data_id or entry.correlation_id}",
                )
            )
        return events


def _parse_error_details(details: object) -> list[AzureApiErrorDetail]:
    """Defensive by construction, never raises - found 2026-10-15: the
    previous code assigned this array straight to a `str | None` field,
    which raised a Pydantic ValidationError on any machine where Azure
    actually populated it, and that exception was swallowed by collect()'s
    blanket except - silently discarding the *entire* PatchOutcome and its
    TimelineEvent for that machine, not just this one field. A malformed
    entry here must degrade to being skipped, not repeat that failure.

    Review caught a narrower repeat of the exact same bug: checking only
    that an entry is a dict isn't enough - a dict with a non-string value
    (e.g. a numeric sub-code, `{"code": 404, "message": "bad"}`) still
    raises inside AzureApiErrorDetail's own string-typed fields, which
    pydantic doesn't coerce. Each entry is now built in its own try/except
    so one malformed value degrades to skipping that one entry, not the
    whole machine."""
    if not isinstance(details, list):
        return []
    parsed = []
    for d in details:
        if not isinstance(d, dict):
            continue
        try:
            parsed.append(AzureApiErrorDetail(code=d.get("code"), message=d.get("message"), target=d.get("target")))
        except ValidationError:
            continue
    return parsed


def _outcome_from_install_result(props: dict) -> PatchOutcome:
    error = props.get("error") if isinstance(props.get("error"), dict) else {}
    return PatchOutcome(
        status=props.get("status", "Unknown"),
        error_code=props.get("errorCode"),
        error_message=error.get("message"),
        error_details=_parse_error_details(error.get("details")),
        packages_failed=[p["patchName"] for p in props.get("patches", []) if p.get("state") == "Failed"] if props.get("patches") else [],
        packages_installed=[p["patchName"] for p in props.get("patches", []) if p.get("state") == "Installed"] if props.get("patches") else [],
        kbs_failed=[p["kbId"] for p in props.get("patches", []) if p.get("state") == "Failed" and p.get("kbId")] if props.get("patches") else [],
        reboot_status=props.get("rebootStatus"),
        started_at=_parse_ts(props.get("startDateTime")),
        ended_at=_parse_ts(props.get("lastModifiedDateTime")),
        window_minutes=props.get("maximumDuration"),
    )


def _summarize_assessment_result(props: dict) -> dict:
    """Builds the detail dict for a 'patch_assessment' TimelineEvent from a
    patchassessmentresources row's properties - same defensive handling as
    _outcome_from_install_result, since this is the identical Azure
    Resource Graph API surface (reuses _parse_error_details for
    `error.details`, the exact "always an array, never a bare string" bug
    already fixed once for install results). Kept JSON-plain (no pydantic
    objects) for the same reason azure_patch_error's own detail dict
    extracts plain fields rather than embedding AzureApiErrorDetail
    objects directly."""
    error = props.get("error") if isinstance(props.get("error"), dict) else {}
    counts = props.get("availablePatchCountByClassification")
    if not isinstance(counts, dict):
        counts = {}
    error_details = _parse_error_details(error.get("details"))
    return {
        "status": props.get("status", "Unknown"),
        "reboot_pending": bool(props.get("rebootPending", False)),
        "available_patch_counts": {k: v for k, v in counts.items() if isinstance(v, int)},
        "error_message": error.get("message"),
        "error_detail_messages": [d.message for d in error_details if d.message],
    }


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
