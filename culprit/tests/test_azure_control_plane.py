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
from datetime import datetime, timezone

from culprit.collectors.azure_control_plane import _INSTALL_RESULT_QUERY, _outcome_from_install_result, _parse_ts

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
        "startDateTime": "2026-10-10T04:00:00Z",
        "lastModifiedDateTime": "2026-10-10T04:18:00Z",
        "maximumDuration": 180,
        "rebootStatus": "NotNeeded",
        "patches": [
            {"patchName": "linux-image-5.15.0-91-generic", "state": "Failed", "kbId": None},
            {"patchName": "curl", "state": "Installed", "kbId": None},
        ],
    }
    outcome = _outcome_from_install_result(props)
    assert outcome.status == "Failed"
    assert outcome.error_code == "PackageManagerFailure"
    assert outcome.packages_failed == ["linux-image-5.15.0-91-generic"]
    assert outcome.packages_installed == ["curl"]
    assert outcome.reboot_status == "NotNeeded"
    assert outcome.window_minutes == 180
    assert outcome.started_at == datetime(2026, 10, 10, 4, 0, tzinfo=timezone.utc)
    assert outcome.ended_at == datetime(2026, 10, 10, 4, 18, tzinfo=timezone.utc)


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
