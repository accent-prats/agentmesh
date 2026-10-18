"""Collector protocol.

Every collector - real (Azure/Datadog/guest) or fixture-backed (demo mode)
- implements the same narrow contract: given a machine and a time window,
return a list of TimelineEvents plus, optionally, a PatchOutcome (only the
control-plane collector actually produces one; the others return `None`
for it). culprit/pipeline/normalize.py is the only thing that merges these
into an EvidenceBundle, so every collector is swappable independently and
the orchestrator never has to know which one is real vs. fixture.

`CollectionRequest.only` lets the orchestrator ask a collector to fetch
*just* the signals named in an RCA agent's `missing_evidence` list on the
second, targeted pass (proposal Section 4: "collection can be
re-dispatched").
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime

from culprit.models.evidence import MachineIdentity, PatchOutcome, Source, TimelineEvent


@dataclass
class CollectionRequest:
    machine: MachineIdentity
    window_start: datetime
    window_end: datetime
    run_id: str
    only: list[str] = field(default_factory=list)  # e.g. ["disk_metrics", "dpkg_log"] - empty means "everything"


@dataclass
class CollectionResult:
    events: list[TimelineEvent]
    outcome: PatchOutcome | None = None
    error: str | None = None  # non-fatal: "guest Run Command timed out after 30s"
    # Structured findings from the guest patch extension's own status file
    # (collectors/patch_extension_status.py) - only guest_linux.py/
    # guest_windows.py ever populate this; every other collector leaves it
    # empty. Kept alongside `events` (which already carry the same facts as
    # TimelineEvents for the RCA prompt) because the UI wants the full
    # structured finding - including the raw status JSON - not just the
    # one-line summary a TimelineEvent carries.
    patch_extension_status: list[dict] = field(default_factory=list)
    # Found 2026-10-19: most guest-level parsers are anomaly-gated (no
    # finding = no TimelineEvent = zero added prompt tokens), which means a
    # check that ran and found nothing looks identical - to both the model
    # and a human reading the UI - to a check that never ran at all. A real
    # RCA cited a vague "evidence gap" about subscription-manager status,
    # even though that check runs unconditionally every scan; there was no
    # way to tell the model (or the user) it had already been checked and
    # was healthy. This records the human-readable name of every section
    # that was genuinely attempted, regardless of whether it found anything
    # - only guest_linux.py/guest_windows.py populate it today, one entry
    # per parsed section (e.g. "subscription-manager status").
    checks_performed: list[str] = field(default_factory=list)
    # Found 2026-10-19 (user-reported follow-up, "show all logs used AND
    # not used, for each VM"): the counterpart to checks_performed above -
    # a section whose marker printed but whose underlying command wasn't
    # even available on this VM (e.g. subscription-manager on a non-RHEL
    # box) is deliberately excluded from checks_performed (see its own
    # exclusion logic in guest_linux.py/guest_windows.py - a "command not
    # found" string must never be read as "checked, healthy"). This
    # records those excluded labels separately so the UI can still show
    # them, honestly labeled as "not available" rather than silently
    # dropping them with no trace at all. Only guest_linux.py/
    # guest_windows.py populate it today, same as checks_performed.
    checks_unavailable: list[str] = field(default_factory=list)
    # Found by review 2026-10-19, same day as checks_unavailable above: the
    # "logs used/not used" UI feature's first draft determined a label's
    # "used" status by matching raw_ref prefixes against the PERSISTED
    # timeline - which db/repository.py::save_machine_outcomes caps at
    # _MAX_PERSISTED_TIMELINE_EVENTS, keeping only the machine's most
    # recent events overall, not per section. A VM stuck in a retry loop
    # producing many uncapped dpkg/journal events could silently evict an
    # unrelated section's own single finding (e.g. SUBMAN's "entitlement
    # expired") from that persisted slice, making the reconciliation
    # wrongly claim "checked, no issues found" for a log that genuinely
    # found something - reintroducing a version of the exact
    # false-confidence problem this whole feature exists to prevent. This
    # records each label's TRUE, uncapped event count at collection time,
    # before any persistence truncation ever happens - the one place that
    # count is still accurate. Originally only guest_linux.py/
    # guest_windows.py populated this (keyed by GuestLogSource.label); a
    # second review the same day found the non-guest collectors
    # (azure_control_plane.py, azure_monitor.py, datadog_collector.py) were
    # just as exposed - azure_monitor.py's Syslog query and datadog_
    # collector.py's logs query are entirely uncapped at the source, so a
    # chatty machine could evict one of their findings from the persisted
    # timeline the exact same way - so all collectors populate this now,
    # keyed by NON_GUEST_LOG_LABELS below for the three non-guest ones.
    checks_finding_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class GuestLogSource:
    """One named log/check a guest collector's script can report on -
    the single source of truth both the collector's own section-label map
    and the reporting layer's "logs used / not used" reconciliation
    (reporting/log_usage_view.py) are built from, so the two can never
    drift out of sync with each other."""

    section: str          # the ---SECTION--- marker in ALLOWED_*_SCRIPT, e.g. "SUBMAN"
    label: str             # human-readable name, e.g. "subscription-manager (entitlement) status"
    # The TimelineEvent.raw_ref prefix this section's own events use - kept
    # as documentation mirroring each parser's own raw_ref=f"..." string
    # (so the two can be visually cross-checked), not a live coupling: the
    # "logs used/not used" reconciliation stopped matching against raw_ref
    # prefixes entirely (see checks_finding_counts above) once that
    # approach was found to silently misreport a finding evicted by the
    # persisted-timeline cap.
    raw_ref_prefix: str


# The non-guest "logs used/not used" rows (reporting/log_usage_view.py) -
# one shared label per Source so a collector and the reporting layer can
# never drift on what to call it, the same reason GuestLogSource exists.
NON_GUEST_LOG_LABELS: dict[Source, str] = {
    Source.AZURE_CONTROL_PLANE: "Azure Resource Graph (patch install/assessment results, Activity Log)",
    Source.AZURE_MONITOR: "Azure Monitor (Log Analytics heartbeat & events)",
    Source.DATADOG_METRIC: "Datadog (metrics, monitors, logs)",
}


def non_guest_finding_counts(source: Source, events: list[TimelineEvent]) -> dict[str, int]:
    """The CollectionResult.checks_finding_counts value for a non-guest
    collector - the whole collector is one row in the "logs used/not used"
    reconciliation (unlike guest collectors, which have one row per
    script section), so this is just the collector's own total event
    count, keyed by its shared NON_GUEST_LOG_LABELS entry. Only ever
    records a nonzero finding (an empty dict, not a zero count, for no
    events) - matching checks_finding_counts' own "only labels with at
    least one event appear here" convention."""
    return {NON_GUEST_LOG_LABELS[source]: len(events)} if events else {}


class Collector(abc.ABC):
    source_name: str

    @abc.abstractmethod
    def collect(self, request: CollectionRequest) -> CollectionResult:
        ...
