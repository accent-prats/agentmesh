"""culprit/collectors/azure_control_plane.py - previously had zero test
coverage, which is exactly how a real bug (the per-machine PatchOutcome
query's `order by` using a bare dynamic-typed sort key) went unnoticed:
Azure Resource Graph rejects that with "(InvalidQuery) ... order operator:
key can't be of dynamic type" on every real invocation, the exception was
caught by collect()'s own blanket except and silently degraded every real
machine's status to normalize.py's generic "Unknown" placeholder - the
exact "status is coming as unknown" symptom reported against a real
tenant run."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest

from culprit.collectors.azure_control_plane import (
    _ASSESSMENT_RESULT_QUERY,
    _INSTALL_RESULT_QUERY,
    _MAX_ACTIVITY_LOG_EVENTS,
    _MAX_PATCH_ERROR_EVENTS,
    AzureControlPlaneCollector,
    _outcome_from_install_result,
    _parse_error_details,
    _parse_ts,
    _summarize_assessment_result,
)
from culprit.collectors.base import CollectionRequest
from culprit.models.evidence import MachineIdentity, OSFamily

# Matches an `order by` clause whose sort key is a bare `properties.foo`
# reference with no cast function wrapped around it - the exact shape
# Resource Graph rejects, since `properties` is a dynamic-typed column.
_BARE_DYNAMIC_ORDER_BY_RE = re.compile(r"order by\s+properties\.\w+", re.IGNORECASE)


def test_install_result_query_never_orders_by_a_bare_dynamic_property():
    """Regression guard for the exact bug: `order by properties.startDateTime`
    (no cast) is what Azure Resource Graph rejects. A `where`/comparison
    on the same dynamic field is fine - only `order by`'s sort key needs
    a cast - so this only checks the order-by clause, not every mention
    of `properties.` in the query."""
    assert not _BARE_DYNAMIC_ORDER_BY_RE.search(_INSTALL_RESULT_QUERY), (
        "order by must cast its dynamic sort key (e.g. tostring(properties.startDateTime)), "
        "not reference the dynamic-typed properties column bare"
    )
    assert "order by tostring(properties.startDateTime)" in _INSTALL_RESULT_QUERY


def test_outcome_from_install_result_builds_a_correct_patch_outcome():
    props = {
        "status": "Failed",
        "errorCode": "PackageManagerFailure",
        "error": {"message": "repo unreachable: connection timed out"},
        "startDateTime": "2026-10-10T04:00:00Z",
        "lastModifiedDateTime": "2026-10-10T04:18:00Z",
        "maximumDuration": 180,
        "rebootStatus": "NotNeeded",
        "patches": [
            {"patchName": "linux-image-5.15.0-91-generic", "state": "Failed", "kbId": None},
            {"patchName": "KB5044284", "state": "Failed", "kbId": "KB5044284"},
            {"patchName": "curl", "state": "Installed", "kbId": None},
        ],
    }
    outcome = _outcome_from_install_result(props)
    assert outcome.status == "Failed"
    assert outcome.error_code == "PackageManagerFailure"
    assert outcome.error_message == "repo unreachable: connection timed out"
    assert outcome.error_details == []
    assert outcome.packages_failed == ["linux-image-5.15.0-91-generic", "KB5044284"]
    assert outcome.packages_installed == ["curl"]
    assert outcome.kbs_failed == ["KB5044284"]
    assert outcome.reboot_status == "NotNeeded"
    assert outcome.window_minutes == 180
    assert outcome.started_at == datetime(2026, 10, 10, 4, 0, tzinfo=timezone.utc)
    assert outcome.ended_at == datetime(2026, 10, 10, 4, 18, tzinfo=timezone.utc)


def test_outcome_from_install_result_handles_a_non_dict_error_field():
    """`error` isn't always a dict - a plain string or missing field must
    degrade to no error_message/error_details, not raise."""
    outcome = _outcome_from_install_result({"error": "a plain string, not a dict"})
    assert outcome.error_message is None
    assert outcome.error_details == []
    assert _outcome_from_install_result({}).error_message is None


def test_outcome_from_install_result_parses_a_real_error_details_array():
    """Regression guard for the exact bug found live 2026-10-15: Azure's
    real `ApiError.details` is always an array of `{code, message, target}`
    objects (confirmed against Microsoft's own REST API reference for
    VirtualMachineInstanceView.patchStatus.lastPatchInstallationSummary.error),
    never a string. The previous code assigned this array straight to a
    `str | None` Pydantic field, raising a ValidationError that
    collect()'s blanket except silently swallowed - discarding the whole
    PatchOutcome (and its TimelineEvent) for any machine where Azure
    actually populated this field. This must not raise, and must come
    back as real, queryable AzureApiErrorDetail objects."""
    props = {
        "status": "Failed",
        "error": {
            "code": "PatchOperationFailed",
            "message": "2 errors reported during patch installation.",
            "details": [
                {"code": "Error", "message": "There is no enough time left to continue applying the next update"},
                {"code": "Error", "message": "There is no enough time left to continue applying the next update"},
            ],
        },
    }
    outcome = _outcome_from_install_result(props)  # must not raise
    assert outcome.error_message == "2 errors reported during patch installation."
    assert len(outcome.error_details) == 2
    assert outcome.error_details[0].code == "Error"
    assert "no enough time left" in outcome.error_details[0].message


def test_parse_error_details_is_defensive_and_never_raises():
    """Every malformed shape degrades to an empty list rather than
    propagating an exception back up into collect()'s try block - the
    whole point of fixing this the way it was fixed."""
    assert _parse_error_details(None) == []
    assert _parse_error_details("not a list") == []
    assert _parse_error_details([]) == []
    assert _parse_error_details(["a plain string, not a dict"]) == []
    mixed = _parse_error_details([{"code": "Error", "message": "ok"}, "garbage"])
    assert len(mixed) == 1
    assert mixed[0].code == "Error" and mixed[0].message == "ok"


def test_parse_error_details_skips_a_well_formed_dict_with_a_non_string_value():
    """Review caught a narrower repeat of the exact bug this module was
    fixed for: a dict entry is the right *container* type, but a numeric
    sub-code (a plausible real Azure payload shape) in `code` still raised
    inside AzureApiErrorDetail's string-typed fields, uncaught, before
    each entry was wrapped in its own try/except. Must degrade to
    skipping only that one entry, not the whole list."""
    result = _parse_error_details([{"code": 404, "message": "bad"}, {"code": "Error", "message": "good"}])
    assert len(result) == 1
    assert result[0].code == "Error" and result[0].message == "good"


def test_outcome_from_install_result_defaults_status_to_unknown_only_when_the_field_is_truly_absent():
    """Unknown as a last-resort default for a row that genuinely has no
    status field is reasonable - the bug was never reaching this function
    at all for a real machine, not this function's own fallback."""
    outcome = _outcome_from_install_result({})
    assert outcome.status == "Unknown"


def test_parse_ts_handles_a_real_iso8601_timestamp():
    assert _parse_ts("2026-10-10T04:00:00Z") == datetime(2026, 10, 10, 4, 0, tzinfo=timezone.utc)


def test_parse_ts_falls_back_to_now_for_missing_or_invalid_input():
    now_before = datetime.now(timezone.utc)
    assert _parse_ts(None) >= now_before
    assert _parse_ts("not a timestamp") >= now_before


# ── patch assessment result (2026-10-18) ─────────────────────────────────────
# Found auditing against a user-supplied "recommended evidence" list:
# patchassessmentresources (missing/available patch counts, assessment
# status) was never queried at all.

def test_assessment_result_query_never_orders_by_a_bare_dynamic_property():
    """Same regression guard as the install-result query above - modeled
    byte-for-byte on it, so it must share the same tostring() cast fix."""
    assert not _BARE_DYNAMIC_ORDER_BY_RE.search(_ASSESSMENT_RESULT_QUERY)
    assert "order by tostring(properties.startDateTime)" in _ASSESSMENT_RESULT_QUERY
    assert "patchassessmentresources" in _ASSESSMENT_RESULT_QUERY


def test_summarize_assessment_result_builds_a_correct_detail_dict():
    props = {
        "status": "Succeeded",
        "rebootPending": True,
        "availablePatchCountByClassification": {"security": 3, "critical": 1, "other": 0},
        "startDateTime": "2026-10-18T08:00:00Z",
        "lastModifiedDateTime": "2026-10-18T08:05:00Z",
    }
    detail = _summarize_assessment_result(props)
    assert detail["status"] == "Succeeded"
    assert detail["reboot_pending"] is True
    assert detail["available_patch_counts"] == {"security": 3, "critical": 1, "other": 0}
    assert detail["error_message"] is None
    assert detail["error_detail_messages"] == []


def test_summarize_assessment_result_is_defensive_against_malformed_fields():
    """Same defensive handling as _outcome_from_install_result - a
    non-dict `error`/`availablePatchCountByClassification`, or a details
    array with a non-string value, must degrade, not raise. Reuses
    _parse_error_details, so this also guards against regressing that bug
    class for the assessment table specifically."""
    detail = _summarize_assessment_result({
        "availablePatchCountByClassification": "not a dict",
        "error": {
            "message": "assessment failed",
            "details": [{"code": 404, "message": "bad"}, {"code": "Error", "message": "good"}],
        },
    })
    assert detail["status"] == "Unknown"
    assert detail["reboot_pending"] is False
    assert detail["available_patch_counts"] == {}
    assert detail["error_message"] == "assessment failed"
    assert detail["error_detail_messages"] == ["good"]  # the malformed entry is skipped, not fatal


# ── collect() tracing (2026-10-17) ───────────────────────────────────────────
# No collect()-level fixture existed before this - built here the same way
# tests/test_guest_collector_timeouts.py bypasses the real Azure SDK, by
# pre-setting the collector's own client attributes directly rather than
# going through _ensure_clients().

class _ExplodingGraphClient:
    def resources(self, request):
        raise RuntimeError("Resource Graph is unavailable")


class _FakeActivityLogs:
    def __init__(self, entries=None):
        self._entries = entries or []

    def list(self, filter):
        return self._entries


class _FakeMonitorClient:
    def __init__(self, activity_entries=None):
        self.activity_logs = _FakeActivityLogs(activity_entries)


class _FakeGraphResult:
    def __init__(self, data):
        self.data = data


class _RoutingGraphClient:
    """collect() now runs two separate Resource Graph queries (install
    result, then assessment result) through the same client - routes by
    which table the query text actually targets so a test can give each
    its own response/exception independently."""
    def __init__(self, install_response=None, assessment_response=None, install_exc=None, assessment_exc=None):
        self._install_response = install_response or _FakeGraphResult([])
        self._assessment_response = assessment_response or _FakeGraphResult([])
        self._install_exc = install_exc
        self._assessment_exc = assessment_exc

    def resources(self, request):
        if "patchassessmentresources" in request.query:
            if self._assessment_exc:
                raise self._assessment_exc
            return self._assessment_response
        if self._install_exc:
            raise self._install_exc
        return self._install_response


def _request():
    now = datetime.now(timezone.utc)
    machine = MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )
    return CollectionRequest(machine=machine, window_start=now - timedelta(hours=3), window_end=now, run_id="run-1")


def test_a_failed_install_result_query_is_traced_but_still_returns_a_collection_gap(caplog):
    """Found 2026-10-17: extended the same tracing discipline added to the
    RCA-provider path to this collector too - the warning must be logged
    alongside the existing (unchanged) error-conversion behavior, which
    must never raise out of collect() (a single machine's query failure
    must degrade, not crash the whole pipeline)."""
    pytest.importorskip("azure.mgmt.monitor")  # optional `culprit[azure]` extra - see pyproject.toml; its own
    # module-level `try: import azure.identity/mgmt.monitor/mgmt.resourcegraph` leaves ALL of them unbound
    # (not just the missing one) if any single one is absent, including QueryRequest this test's fakes need.
    collector = AzureControlPlaneCollector(credential=object())
    collector._graph_client = _ExplodingGraphClient()
    collector._monitor_client = _FakeMonitorClient()
    collector._ensure_clients = lambda subscription_id: None  # bypass the real SDK-availability check entirely

    with caplog.at_level("WARNING"):
        result = collector.collect(_request())

    assert result.error is not None and "Resource Graph query failed" in result.error  # unchanged behavior
    assert any(
        r.levelname == "WARNING" and "azure_control_plane: install-result query for vm-1 failed" in r.message and "RuntimeError" in r.message
        for r in caplog.records
    )


def _collector_with(install_response=None, assessment_response=None, install_exc=None, assessment_exc=None, activity_entries=None):
    pytest.importorskip("azure.mgmt.monitor")
    collector = AzureControlPlaneCollector(credential=object())
    collector._graph_client = _RoutingGraphClient(install_response, assessment_response, install_exc, assessment_exc)
    collector._monitor_client = _FakeMonitorClient(activity_entries)
    collector._ensure_clients = lambda subscription_id: None
    return collector


def test_a_successful_assessment_result_produces_a_patch_assessment_event():
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchassessmentresults/x",
        "properties": {
            "status": "Succeeded",
            "rebootPending": False,
            "availablePatchCountByClassification": {"security": 2, "other": 1},
            "lastModifiedDateTime": "2026-10-18T08:05:00Z",
        },
    }])
    collector = _collector_with(assessment_response=response)

    result = collector.collect(_request())

    assessment_events = [e for e in result.events if e.kind == "patch_assessment"]
    assert len(assessment_events) == 1
    assert "Succeeded" in assessment_events[0].summary
    assert "3 patch(es) pending" in assessment_events[0].summary
    assert assessment_events[0].detail["available_patch_counts"] == {"security": 2, "other": 1}


def test_a_failed_assessment_result_query_is_traced_but_still_returns_a_collection_gap(caplog):
    collector = _collector_with(assessment_exc=RuntimeError("assessment table unavailable"))

    with caplog.at_level("WARNING"):
        result = collector.collect(_request())

    assert result.error is not None and "Assessment query failed" in result.error
    assert any(
        r.levelname == "WARNING" and "azure_control_plane: assessment-result query for vm-1 failed" in r.message and "RuntimeError" in r.message
        for r in caplog.records
    )


# ── Activity Log cap/filter (2026-10-18) ─────────────────────────────────────
# Found answering a direct "will this bloat LLM token usage" question: a
# real production run logged "activity-log query ... returned 262
# event(s)" for a single machine - one TimelineEvent per raw row, no cap,
# most of them routine reads.

class _FakeOperationName:
    def __init__(self, value):
        self.value = value
        self.localized_value = value


class _FakeStatus:
    def __init__(self, value):
        self.value = value


class _FakeActivityLogEntry:
    def __init__(self, operation_value, status_value="Succeeded", ts=None, event_id="id"):
        self.operation_name = _FakeOperationName(operation_value)
        self.status = _FakeStatus(status_value)
        self.event_timestamp = ts or datetime.now(timezone.utc)
        self.caller = "user@example.com"
        self.event_data_id = event_id
        self.correlation_id = None


def test_activity_log_drops_routine_reads_but_keeps_writes_and_failures():
    entries = [
        _FakeActivityLogEntry("Microsoft.Compute/virtualMachines/read", "Succeeded", event_id="read-1"),
        _FakeActivityLogEntry("Microsoft.Compute/virtualMachines/read", "Succeeded", event_id="read-2"),
        _FakeActivityLogEntry("Microsoft.Compute/virtualMachines/write", "Succeeded", event_id="write-1"),
        _FakeActivityLogEntry("Microsoft.Compute/virtualMachines/read", "Failed", event_id="failed-read"),
    ]
    collector = _collector_with(activity_entries=entries)

    result = collector.collect(_request())

    kept_refs = {e.raw_ref for e in result.events if e.kind == "activity_log"}
    assert kept_refs == {"activitylog:write-1", "activitylog:failed-read"}


def test_activity_log_caps_at_the_max_even_after_filtering_keeping_most_recent():
    now = datetime.now(timezone.utc)
    entries = [
        _FakeActivityLogEntry(
            "Microsoft.Compute/virtualMachines/write", "Succeeded",
            ts=now - timedelta(minutes=i), event_id=f"write-{i}",
        )
        for i in range(_MAX_ACTIVITY_LOG_EVENTS + 10)
    ]
    collector = _collector_with(activity_entries=entries)

    result = collector.collect(_request())

    activity_events = [e for e in result.events if e.kind == "activity_log"]
    assert len(activity_events) == _MAX_ACTIVITY_LOG_EVENTS
    # most-recent-first: write-0 (now) must survive, write-{last} (oldest) must not
    kept_refs = {e.raw_ref for e in activity_events}
    assert "activitylog:write-0" in kept_refs
    assert f"activitylog:write-{_MAX_ACTIVITY_LOG_EVENTS + 9}" not in kept_refs


def test_activity_log_logs_only_when_the_filter_actually_reduced_the_count(caplog):
    entries = [_FakeActivityLogEntry("Microsoft.Compute/virtualMachines/read", "Succeeded", event_id="read-1")]
    collector = _collector_with(activity_entries=entries)

    with caplog.at_level("INFO"):
        collector.collect(_request())

    assert any("activity log for vm-1 had 1 event(s), kept 0 after filtering" in r.message for r in caplog.records)


def test_activity_log_logs_nothing_extra_when_nothing_was_filtered(caplog):
    entries = [_FakeActivityLogEntry("Microsoft.Compute/virtualMachines/write", "Succeeded", event_id="write-1")]
    collector = _collector_with(activity_entries=entries)

    with caplog.at_level("INFO"):
        collector.collect(_request())

    assert not any("kept" in r.message and "after filtering" in r.message for r in caplog.records)


# A real production message (2026-10-18): Azure's own install-error detail
# routinely runs past the app-wide 240-char summary convention, and the part
# it cuts off is exactly the diagnostic signal worth giving the RCA - the
# hResult code and the troubleshooting link.
_REAL_LONG_INSTALL_ERROR_MESSAGE = (
    "Failed to assess and install update [2026-10 Cumulative Update for Microsoft server operating "
    "system version 21H2 for x64-based Systems (KB5126655)]. Reason: [Failed to install Update 2026-10 "
    "Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems "
    "(KB5126655), result code=Failed, hResult:0x80070002. For information on diagnosing this error, "
    "see https://aka.ms/TroubleshootVMGuestPatching.]"
)


def test_azure_patch_error_summary_keeps_the_full_message_including_the_troubleshooting_link():
    """2026-10-18: the previous 240-char cap silently truncated this real
    message before the hResult code and before Azure's own troubleshooting
    link - exactly the kind of corrective guidance the user asked Culprit
    to feed into RCA. The raised cap (_PATCH_ERROR_SUMMARY_MAX_CHARS) must
    comfortably fit it."""
    assert len(_REAL_LONG_INSTALL_ERROR_MESSAGE) > 240  # pin the premise: this message really did exceed the old cap

    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchinstallationresults/x",
        "properties": {
            "status": "Failed",
            "errorCode": "PatchInstallFailed",
            "lastModifiedDateTime": "2026-10-18T08:05:00Z",
            "error": {
                "message": "1 errors reported.",
                "details": [{"code": "Error", "message": _REAL_LONG_INSTALL_ERROR_MESSAGE}],
            },
        },
    }])
    collector = _collector_with(install_response=response)

    result = collector.collect(_request())

    error_events = [e for e in result.events if e.kind == "azure_patch_error"]
    assert len(error_events) == 1
    assert "hResult:0x80070002" in error_events[0].summary
    assert "https://aka.ms/TroubleshootVMGuestPatching" in error_events[0].summary


def test_a_failed_assessment_result_produces_its_own_error_events():
    """Before this fix, a FAILED assessment's own Azure-reported reasons
    (error.details[]) only ever landed in the patch_assessment event's
    `detail` dict, which render_timeline_text() never sends to the model -
    so this evidence was collected but silently never reached the RCA."""
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchassessmentresults/x",
        "properties": {
            "status": "Failed",
            "rebootPending": False,
            "lastModifiedDateTime": "2026-10-18T08:05:00Z",
            "error": {
                "message": "assessment failed",
                "details": [{"code": "Error", "message": "Could not reach Windows Update service"}],
            },
        },
    }])
    collector = _collector_with(assessment_response=response)

    result = collector.collect(_request())

    error_events = [e for e in result.events if e.kind == "azure_assessment_error"]
    assert len(error_events) == 1
    assert "Could not reach Windows Update service" in error_events[0].summary


def test_a_successful_assessment_result_produces_no_assessment_error_events():
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchassessmentresults/x",
        "properties": {
            "status": "Succeeded",
            "rebootPending": False,
            "availablePatchCountByClassification": {"security": 2},
            "lastModifiedDateTime": "2026-10-18T08:05:00Z",
        },
    }])
    collector = _collector_with(assessment_response=response)

    result = collector.collect(_request())

    assert not [e for e in result.events if e.kind == "azure_assessment_error"]


def test_azure_patch_error_events_are_capped_defensively():
    """Defense-in-depth found by review: _INSTALL_RESULT_QUERY/
    _ASSESSMENT_RESULT_QUERY both `limit 1`, but error.details[] itself has
    no enforced length limit from Azure's API/schema - the 600-char-per-
    event cap's safety argument rests on an observed real-world UI showing
    "the latest 3 errors are shared in details," not a guarantee. Mirrors
    _MAX_ACTIVITY_LOG_EVENTS rather than trusting that observation to hold
    for every tenant/error shape."""
    many_details = [{"code": "Error", "message": f"error number {i}"} for i in range(_MAX_PATCH_ERROR_EVENTS + 5)]
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchinstallationresults/x",
        "properties": {
            "status": "Failed",
            "errorCode": "PatchInstallFailed",
            "lastModifiedDateTime": "2026-10-18T08:05:00Z",
            "error": {"message": "many errors reported.", "details": many_details},
        },
    }])
    collector = _collector_with(install_response=response)

    result = collector.collect(_request())

    error_events = [e for e in result.events if e.kind == "azure_patch_error"]
    assert len(error_events) == _MAX_PATCH_ERROR_EVENTS


def test_azure_assessment_error_events_are_capped_defensively():
    many_messages = [f"error number {i}" for i in range(_MAX_PATCH_ERROR_EVENTS + 5)]
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchassessmentresults/x",
        "properties": {
            "status": "Failed",
            "rebootPending": False,
            "lastModifiedDateTime": "2026-10-18T08:05:00Z",
            "error": {
                "message": "assessment failed",
                "details": [{"code": "Error", "message": m} for m in many_messages],
            },
        },
    }])
    collector = _collector_with(assessment_response=response)

    result = collector.collect(_request())

    error_events = [e for e in result.events if e.kind == "azure_assessment_error"]
    assert len(error_events) == _MAX_PATCH_ERROR_EVENTS


# A real production case (2026-10-18): a patchinstallationresults row whose
# `error.details[]` was empty but whose top-level `error.message` carried
# the ENTIRE real diagnostic text (confirmed directly against the Azure
# Portal's own "Update deployment run" pane for the same operation) -
# previously invisible to the RCA model, which then fabricated a wrong
# hResult code and a nonexistent "vendor documentation" citation rather
# than admitting it had no real detail.
_REAL_MESSAGE_ONLY_ERROR = (
    "\"1 errors reported. The latest 3 errors are shared in details. To view all errors, review "
    "this log file on the machine: [C:\\WindowsAzure\\Logs\\Plugins\\Microsoft.CPlat.Core."
    "WindowsPatchExtension\\1.5.85] [\"Failed to assess and install update [2026-10 Cumulative "
    "Update for Microsoft server operating system version 21H2 for x64-based Systems "
    "(KB5126655)]. Reason: [Failed to install Update 2026-10 Cumulative Update for Microsoft "
    "server operating system version 21H2 for x64-based Systems (KB5126655), result "
    "code=Failed, hResult: 0x80070002.. For information on diagnosing this error, see "
    "https://aka.ms/TroubleshootVMGuestPatching.]\"]"
)


def test_install_result_falls_back_to_the_top_level_error_message_when_details_is_empty():
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchinstallationresults/8772a0f9",
        "properties": {
            "status": "Failed",
            "lastModifiedDateTime": "2026-10-16T04:28:49Z",
            "error": {"message": _REAL_MESSAGE_ONLY_ERROR, "details": []},
        },
    }])
    collector = _collector_with(install_response=response)

    result = collector.collect(_request())

    error_events = [e for e in result.events if e.kind == "azure_patch_error"]
    assert len(error_events) == 1
    assert "hResult: 0x80070002" in error_events[0].summary
    assert "https://aka.ms/TroubleshootVMGuestPatching" in error_events[0].summary
    assert error_events[0].raw_ref == "resourcegraph:/subscriptions/s/.../patchinstallationresults/8772a0f9:error_message"


def test_install_result_prefers_error_details_over_the_top_level_message_when_both_exist():
    """The fallback must not duplicate real per-detail events - when
    error.details[] is populated, the top-level error.message (often just
    a terse "N errors reported" meta-summary) is not surfaced separately."""
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchinstallationresults/x",
        "properties": {
            "status": "Failed",
            "lastModifiedDateTime": "2026-10-16T04:28:49Z",
            "error": {
                "message": "1 errors reported.",
                "details": [{"code": "Error", "message": "the real detailed reason"}],
            },
        },
    }])
    collector = _collector_with(install_response=response)

    result = collector.collect(_request())

    error_events = [e for e in result.events if e.kind == "azure_patch_error"]
    assert len(error_events) == 1
    assert "the real detailed reason" in error_events[0].summary
    assert "1 errors reported" not in error_events[0].summary


def test_install_result_with_no_error_message_and_no_details_produces_no_error_event():
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchinstallationresults/x",
        "properties": {"status": "Failed", "lastModifiedDateTime": "2026-10-16T04:28:49Z"},
    }])
    collector = _collector_with(install_response=response)

    result = collector.collect(_request())

    assert not [e for e in result.events if e.kind == "azure_patch_error"]


def test_assessment_result_falls_back_to_the_top_level_error_message_when_details_is_empty():
    response = _FakeGraphResult([{
        "id": "/subscriptions/s/.../patchassessmentresults/x",
        "properties": {
            "status": "Failed",
            "rebootPending": False,
            "lastModifiedDateTime": "2026-10-18T08:05:00Z",
            "error": {"message": "Could not reach Windows Update service", "details": []},
        },
    }])
    collector = _collector_with(assessment_response=response)

    result = collector.collect(_request())

    error_events = [e for e in result.events if e.kind == "azure_assessment_error"]
    assert len(error_events) == 1
    assert "Could not reach Windows Update service" in error_events[0].summary
