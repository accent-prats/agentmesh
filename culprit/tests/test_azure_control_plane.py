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
    _INSTALL_RESULT_QUERY,
    AzureControlPlaneCollector,
    _outcome_from_install_result,
    _parse_error_details,
    _parse_ts,
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


# ── collect() tracing (2026-10-17) ───────────────────────────────────────────
# No collect()-level fixture existed before this - built here the same way
# tests/test_guest_collector_timeouts.py bypasses the real Azure SDK, by
# pre-setting the collector's own client attributes directly rather than
# going through _ensure_clients().

class _ExplodingGraphClient:
    def resources(self, request):
        raise RuntimeError("Resource Graph is unavailable")


class _FakeActivityLogs:
    def list(self, filter):
        return []


class _FakeMonitorClient:
    def __init__(self):
        self.activity_logs = _FakeActivityLogs()


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
