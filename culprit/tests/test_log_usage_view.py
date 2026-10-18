"""reporting/log_usage_view.py - the "logs used / not used, with reason"
reconciliation shown inside the machine page's "Show full timeline" panel
(added 2026-10-19, user-requested follow-up to checks_performed: "add all
logs being used and also the logs not used in analysis, with a brief
reason, for each VM"). Pure-function tests against the view builder
directly - end-to-end rendering is covered by test_log_usage_ui.py.

"used" status (guest AND non-guest rows alike) is determined ENTIRELY from
checks_finding_counts, never from a persisted timeline - a first version
of this feature matched raw_ref prefixes against the persisted timeline,
found by review 2026-10-19 to be unsound (that timeline is capped at
_MAX_PERSISTED_TIMELINE_EVENTS and could evict a genuine finding, wrongly
reporting "no issues found")."""
from __future__ import annotations

from culprit.models.evidence import OSFamily
from culprit.reporting.log_usage_view import build_log_usage_view

_AZURE_LABEL = "Azure Resource Graph (patch install/assessment results, Activity Log)"
_MONITOR_LABEL = "Azure Monitor (Log Analytics heartbeat & events)"
_DATADOG_LABEL = "Datadog (metrics, monitors, logs)"

_ALL_ATTEMPTED = ["azure_control_plane", "guest_linux", "azure_monitor", "datadog_metric"]


def _by_label(entries, label):
    return next(e for e in entries if e.label == label)


def test_empty_sources_attempted_suppresses_the_whole_view():
    """A real, current run's sources_attempted is never actually empty
    (every collection fan-out dispatches at least the control-plane
    collector) - an empty list means this run's record predates the
    feature, not that nothing was attempted. Showing synthetic "not
    configured" rows for a run this data was never captured for would be
    actively misleading, so the whole view is suppressed instead."""
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=["disk usage"],
        checks_unavailable=[], collection_gaps=[], sources_attempted=[],
    )
    assert entries == []


def test_guest_section_used_when_it_has_a_finding_count():
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=[], checks_unavailable=[],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
        checks_finding_counts={"dpkg package manager log": 3},
    )
    dpkg = _by_label(entries, "dpkg package manager log")
    assert dpkg.status == "used"
    assert "3 findings" in dpkg.reason


def test_guest_section_used_survives_a_capped_persisted_timeline():
    """Found by review 2026-10-19: a VM producing many events elsewhere
    (e.g. a dpkg retry loop) can push the persisted timeline past
    _MAX_PERSISTED_TIMELINE_EVENTS, evicting an unrelated section's own
    single finding - a version of this reconciliation that matched against
    that capped timeline would wrongly report "no issues found" for a log
    that genuinely found something. This reconciliation no longer accepts
    a timeline argument at all - checks_finding_counts is the sole
    authority - so there is nothing left to evict; this test pins that by
    asserting "used" from checks_finding_counts alone."""
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=["subscription-manager (entitlement) status"], checks_unavailable=[],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
        checks_finding_counts={"subscription-manager (entitlement) status": 1},
    )
    subman = _by_label(entries, "subscription-manager (entitlement) status")
    assert subman.status == "used"
    assert "1 finding" in subman.reason


def test_guest_section_healthy_when_in_checks_performed():
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=["disk usage"], checks_unavailable=[],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
    )
    disk = _by_label(entries, "disk usage")
    assert disk.status == "no_issues"


def test_guest_section_unavailable_when_in_checks_unavailable():
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=[], checks_unavailable=["subscription-manager (entitlement) status"],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
    )
    subman = _by_label(entries, "subscription-manager (entitlement) status")
    assert subman.status == "unavailable"
    assert "isn't installed" in subman.reason


def test_guest_section_not_collected_when_the_whole_collector_failed():
    """When guest_linux's Run Command fails entirely, no guest label
    appears in checks_performed/checks_unavailable/checks_finding_counts -
    every guest row falls back to the collection_gaps text for that source."""
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=[], checks_unavailable=[],
        collection_gaps=["guest_linux: Run Command failed: timed out after 61.2s"],
        sources_attempted=_ALL_ATTEMPTED,
    )
    disk = _by_label(entries, "disk usage")
    assert disk.status == "not_collected"
    assert "timed out" in disk.reason


def test_windows_vm_shows_no_linux_rows_and_vice_versa():
    entries = build_log_usage_view(
        OSFamily.WINDOWS, checks_performed=[], checks_unavailable=[],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
    )
    labels = {e.label for e in entries}
    assert "dpkg package manager log" not in labels
    assert "Windows Update log" in labels


def test_unknown_os_family_shows_no_guest_rows():
    entries = build_log_usage_view(
        OSFamily.UNKNOWN, checks_performed=[], checks_unavailable=[],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
    )
    assert not any("log" in e.label.lower() and "Azure" not in e.label and "Datadog" not in e.label for e in entries)


def test_non_guest_source_used_when_it_has_a_finding_count():
    """Found by the same 2026-10-19 review, for a different reason: the
    Azure Monitor Syslog query and the Datadog logs query are both
    genuinely uncapped at the source, so non-guest rows are exposed to the
    identical eviction risk guest rows were - checks_finding_counts is the
    sole "used" authority for these rows too now, not just guest ones."""
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=[], checks_unavailable=[],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
        checks_finding_counts={_DATADOG_LABEL: 2},
    )
    datadog = _by_label(entries, _DATADOG_LABEL)
    assert datadog.status == "used"
    assert "2 findings" in datadog.reason


def test_non_guest_source_not_configured_when_never_attempted():
    """The core case this field exists for: Datadog not being in
    sources_attempted at all (no collector was ever dispatched for it -
    not configured for this environment) must read differently from
    "attempted and found nothing.\""""
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=[], checks_unavailable=[],
        collection_gaps=[], sources_attempted=["azure_control_plane", "guest_linux"],
    )
    datadog = _by_label(entries, _DATADOG_LABEL)
    monitor = _by_label(entries, _MONITOR_LABEL)
    assert datadog.status == "not_configured"
    assert monitor.status == "not_configured"
    assert "not configured" in datadog.reason.lower()


def test_non_guest_source_healthy_when_attempted_and_silent():
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=[], checks_unavailable=[],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
    )
    monitor = _by_label(entries, _MONITOR_LABEL)
    assert monitor.status == "no_issues"


def test_non_guest_source_not_collected_when_attempted_and_failed():
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=[], checks_unavailable=[],
        collection_gaps=["datadog_metric: API request failed: 503"],
        sources_attempted=_ALL_ATTEMPTED,
    )
    datadog = _by_label(entries, _DATADOG_LABEL)
    assert datadog.status == "not_collected"
    assert "503" in datadog.reason


def test_azure_control_plane_used_when_it_has_a_finding_count():
    entries = build_log_usage_view(
        OSFamily.LINUX, checks_performed=[], checks_unavailable=[],
        collection_gaps=[], sources_attempted=_ALL_ATTEMPTED,
        checks_finding_counts={_AZURE_LABEL: 1},
    )
    azure = _by_label(entries, _AZURE_LABEL)
    assert azure.status == "used"
