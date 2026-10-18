"""Builds the "logs used / not used, with reason" reconciliation shown
inside the machine page's "Show full timeline" panel (added 2026-10-19,
user-requested: "add all logs being used and also the logs not used in
analysis, with a brief user-understandable reason, for each VM" - the
same complaint, one level more complete, as the one that originally led
to EvidenceBundle.checks_performed: "Show full timeline still only shows
the resourcegraph logs, no reference to other logs being used").

Reconciles signals that already exist for other reasons, rather than
collecting anything new:
  - checks_finding_counts - every collector's TRUE, uncapped event count
    from collection time ("used in analysis", with the real count), keyed
    by label - one label per guest-OS section (collectors/base.py::
    GuestLogSource) or per non-guest collector (collectors/base.py::
    NON_GUEST_LOG_LABELS). This is the ONLY signal "used" is ever
    determined from - deliberately never the persisted timeline
    (db/repository.py::_MAX_PERSISTED_TIMELINE_EVENTS caps it to the
    machine's most recent events overall), which could silently evict a
    genuine finding and make this reconciliation wrongly claim "no issues
    found." Found by review 2026-10-19 for the guest rows first; a second
    review the same day found the non-guest collectors (azure_monitor.py's
    Syslog query, datadog_collector.py's logs query - both genuinely
    uncapped at the source) were just as exposed, so every collector
    populates this now, not just the guest ones.
  - checks_performed / checks_unavailable - guest-OS sections genuinely
    attempted this run, healthy-and-silent or tool-not-installed
    (collectors/guest_linux.py, collectors/guest_windows.py)
  - collection_gaps / sources_attempted - whether the collector behind a
    row was even dispatched this run at all. For non-guest sources (Azure
    Monitor, Datadog) this answers "was this source even configured for
    this environment" (optional collectors, see api/deps.py). For guest
    rows this is normally a no-op on a real run (GUEST_LINUX/GUEST_WINDOWS
    are always dispatched for a matching machine), but a demo/fixture
    EvidenceBundle can legitimately narrow sources_attempted to test a
    different scenario - found by review 2026-10-19 reproduced on 24 of 47
    demo machines, where every guest row wrongly read "not collected"
    (implying an attempt that found nothing) instead of "not attempted."

This is presentation logic over already-collected/persisted data, not a
new parsing pass - the same division of labor as extension_status_view.py/
evidence_timeline_view.py."""
from __future__ import annotations

from dataclasses import dataclass

from culprit.collectors.base import NON_GUEST_LOG_LABELS
from culprit.collectors.guest_linux import GUEST_LOG_SOURCES as _LINUX_LOG_SOURCES
from culprit.collectors.guest_windows import GUEST_LOG_SOURCES as _WINDOWS_LOG_SOURCES
from culprit.models.evidence import OSFamily, Source

# status -> (short label, badge color, icon) - same three-tuple convention
# as extension_status_view.py's _STATUS_DISPLAY.
_STATUS_DISPLAY: dict[str, tuple[str, str, str]] = {
    "used": ("Used in analysis", "emerald", "check-circle"),
    "no_issues": ("Checked — no issues found", "gray", "circle-check"),
    "unavailable": ("Not available on this VM", "gray", "circle-slash"),
    "not_collected": ("Not collected", "amber", "alert-triangle"),
    "not_configured": ("Not configured", "gray", "minus-circle"),
    "not_attempted": ("Not attempted this run", "gray", "circle-dashed"),
}


@dataclass(frozen=True)
class LogUsageEntry:
    label: str
    status: str
    status_label: str
    badge_color: str
    icon: str
    reason: str


def _entry(label: str, status: str, reason: str) -> LogUsageEntry:
    status_label, badge_color, icon = _STATUS_DISPLAY[status]
    return LogUsageEntry(label=label, status=status, status_label=status_label, badge_color=badge_color, icon=icon, reason=reason)


def _guest_entries(
    os_family: OSFamily, checks_performed: list[str], checks_unavailable: list[str],
    collection_gaps: list[str], sources_attempted: list[str], checks_finding_counts: dict[str, int],
) -> list[LogUsageEntry]:
    if os_family == OSFamily.LINUX:
        sources, collector_source = _LINUX_LOG_SOURCES, Source.GUEST_LINUX
    elif os_family == OSFamily.WINDOWS:
        sources, collector_source = _WINDOWS_LOG_SOURCES, Source.GUEST_WINDOWS
    else:
        return []  # unknown OS - neither script ever ran, nothing to reconcile

    # Found by review 2026-10-19 (reproduced live on 24 of 47 demo
    # machines, whose fixtures deliberately never dispatch a guest
    # collector for a control-plane/Azure-Monitor-only scenario): without
    # this check, EVERY guest row for such a machine fell through to the
    # generic "not_collected" bucket below, wording that implies an
    # attempt was made and came back empty - wrong when the collector was
    # never even dispatched this run. On a real live run this can't
    # happen (GUEST_LINUX/GUEST_WINDOWS are registered unconditionally in
    # api/deps.py and filtered only by OS match, so a matching machine's
    # own guest collector is always in sources_attempted), but a demo/
    # fixture EvidenceBundle can legitimately narrow sources_attempted to
    # test a different code path, and the UI must say so honestly rather
    # than guess.
    if collector_source.value not in sources_attempted:
        return [
            _entry(src.label, "not_attempted", "Guest log collection wasn't dispatched for this machine this run.")
            for src in sources
        ]

    collector_gap = next((g for g in collection_gaps if g.startswith(f"{collector_source.value}:")), None)
    entries = []
    for src in sources:
        # "used" is determined from checks_finding_counts (the TRUE,
        # uncapped per-section count recorded at collection time -
        # collectors/base.py::CollectionResult.checks_finding_counts),
        # never from the persisted timeline - found by review 2026-10-19:
        # that timeline is capped to the machine's most recent events
        # overall (db/repository.py::_MAX_PERSISTED_TIMELINE_EVENTS), so a
        # VM producing many uncapped dpkg/journal events could silently
        # evict an unrelated section's own finding from the persisted
        # slice, making this reconciliation wrongly claim "no issues
        # found" for a log that genuinely found something.
        count = checks_finding_counts.get(src.label, 0)
        if count:
            entries.append(_entry(src.label, "used", f"{count} finding{'s' if count != 1 else ''} included in the analysis above."))
        elif src.label in checks_performed:
            entries.append(_entry(src.label, "no_issues", "Checked this run — nothing anomalous found."))
        elif src.label in checks_unavailable:
            entries.append(_entry(src.label, "unavailable", "The required tool isn't installed on this VM, so this check could not run."))
        elif collector_gap:
            entries.append(_entry(src.label, "not_collected", collector_gap.split(": ", 1)[-1]))
        else:
            # Genuinely residual: the OS matches and there's no whole-collector
            # gap, yet this one label is absent from every other bucket - a
            # truncated/partial Run Command output is the most plausible real
            # cause. Honest about not knowing more than that.
            entries.append(_entry(src.label, "not_collected", "No data returned for this check this run."))
    return entries


def _non_guest_entries(
    collection_gaps: list[str], sources_attempted: list[str], checks_finding_counts: dict[str, int],
) -> list[LogUsageEntry]:
    entries = []
    for source, label in NON_GUEST_LOG_LABELS.items():
        count = checks_finding_counts.get(label, 0)
        gap = next((g for g in collection_gaps if g.startswith(f"{source.value}:")), None)
        if count:
            entries.append(_entry(label, "used", f"{count} finding{'s' if count != 1 else ''} included in the analysis above."))
        elif gap:
            entries.append(_entry(label, "not_collected", gap.split(": ", 1)[-1]))
        elif source.value not in sources_attempted:
            entries.append(_entry(label, "not_configured", "Not configured for this environment - no data to check."))
        else:
            entries.append(_entry(label, "no_issues", "Checked this run — nothing anomalous found."))
    return entries


def build_log_usage_view(
    os_family: OSFamily, checks_performed: list[str], checks_unavailable: list[str],
    collection_gaps: list[str], sources_attempted: list[str], checks_finding_counts: dict[str, int] | None = None,
) -> list[LogUsageEntry]:
    """The guest-OS, per-log-file rows (detailed - CBS.log, dpkg.log,
    subscription-manager, etc.) followed by the coarser, source-level rows
    for Azure Monitor/Datadog - deliberately in that order, since the
    guest rows are the ones a user can act on file-by-file, while the
    source-level rows are closer to "is this integration even turned on."

    `checks_finding_counts` is the ONLY authority for whether any row -
    guest or non-guest - is "used"; this function never looks at the
    persisted timeline at all (an earlier version did, for guest rows
    first and non-guest rows a little longer - see checks_finding_counts'
    own docstring in collectors/base.py for why that was found unsound:
    the persisted timeline is capped and can evict a genuine finding,
    which would make this reconciliation wrongly claim "no issues found").
    `checks_finding_counts` defaults to `{}` (not an error) for a run
    predating this field - every row then falls back to the honest "no
    data returned"/"checked, no issues" bucket, same as any other missing
    signal.

    Returns [] when `sources_attempted` is empty - a real, current run's
    EvidenceBundle.sources_attempted is NEVER actually empty (every
    collection fan-out dispatches at least the control-plane collector,
    see pipeline/collection.py), so an empty list here is the signal that
    this run's MachineOutcomeRecord predates this field (or has none at
    all), not that nothing was attempted. Showing synthetic "not
    configured"/"not collected" rows in that case would be actively
    misleading about a run this data was simply never captured for -
    worse than showing nothing, the same discipline this whole feature
    exists to enforce elsewhere."""
    if not sources_attempted:
        return []
    counts = checks_finding_counts or {}
    return _guest_entries(os_family, checks_performed, checks_unavailable, collection_gaps, sources_attempted, counts) + \
        _non_guest_entries(collection_gaps, sources_attempted, counts)
