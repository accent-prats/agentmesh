"""normalize.py::merge_recollection - re-merging a targeted recollection
pass's fresh per-source results into an already-merged EvidenceBundle.

Found 2026-10-19 from a real production run (tcx-tenant): pipeline/
orchestrator.py's recollection pass only ever fed its new events into a
transient bundle for a second RCA-agent call - never back into what
save_machine_outcomes() actually persists - so a guest collector that
genuinely recovered real data on its retry still showed as "not collected"
on the machine page. These tests pin merge_recollection()'s own replace-
not-add semantics directly (independent of the end-to-end orchestrator
wiring, which test_recollection_persists_to_the_machine_outcome.py covers).
"""
from __future__ import annotations

from datetime import datetime, timezone

from culprit.collectors.base import CollectionResult, event_sources_for
from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.pipeline.normalize import merge_recollection

_SUBMAN_LABEL = "subscription-manager (entitlement) status"
_DISK_LABEL = "disk usage"
_CONTROL_PLANE_LABEL = "Azure Resource Graph (patch install/assessment results, Activity Log)"


def _machine() -> MachineIdentity:
    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )


def _event(source: Source, kind: str, raw_ref: str, summary: str = "x") -> TimelineEvent:
    return TimelineEvent(
        ts=datetime(2026, 10, 19, tzinfo=timezone.utc), source=source, kind=kind, summary=summary, raw_ref=raw_ref,
    )


def _original() -> EvidenceBundle:
    """Models the real reported scenario: guest_linux's first pass only
    partially succeeded (a stale subman finding, no disk-usage data at
    all), while azure_control_plane succeeded cleanly and is untouched by
    the recollection."""
    return EvidenceBundle(
        run_id="run-1", machine=_machine(), outcome=PatchOutcome(status="Failed"),
        collection_started_at=datetime(2026, 10, 19, tzinfo=timezone.utc),
        timeline=[
            _event(Source.GUEST_LINUX, "subman_status", "guest:subman:vm-1:0", "entitlement expired"),
            _event(Source.AZURE_CONTROL_PLANE, "patch_install_result", "resourcegraph:install:vm-1"),
        ],
        sources_attempted=[Source.GUEST_LINUX, Source.AZURE_CONTROL_PLANE],
        sources_succeeded=[Source.AZURE_CONTROL_PLANE],
        collection_gaps=["guest_linux: Run Command timed out after 60s"],
        checks_performed=[_SUBMAN_LABEL],
        checks_unavailable=[],
        checks_finding_counts={_SUBMAN_LABEL: 1, _CONTROL_PLANE_LABEL: 1},
    )


def test_a_recollected_sources_stale_finding_is_removed_not_kept():
    """The core correctness property: a label the first pass reported a
    finding for, which the fresh retry's complete re-collection simply
    doesn't mention any more, must not survive the merge as a stale,
    no-longer-true finding."""
    original = _original()
    new_results = {
        Source.GUEST_LINUX: CollectionResult(
            events=[_event(Source.GUEST_LINUX, "disk_usage", "guest:disk:vm-1:0", "disk nearly full")],
            checks_performed=[_SUBMAN_LABEL, _DISK_LABEL],  # subman checked again, found healthy this time
            checks_finding_counts={_DISK_LABEL: 1},  # no subman entry at all any more
        ),
    }

    merged = merge_recollection(original, new_results)

    assert merged.checks_finding_counts == {_DISK_LABEL: 1, _CONTROL_PLANE_LABEL: 1}
    assert _SUBMAN_LABEL not in merged.checks_finding_counts


def test_a_recollected_sources_stale_timeline_event_is_removed_too():
    """Internal consistency: a timeline event must not outlive the finding
    count it was based on - the model's prompt and the persisted record
    must agree."""
    original = _original()
    new_results = {
        Source.GUEST_LINUX: CollectionResult(
            events=[_event(Source.GUEST_LINUX, "disk_usage", "guest:disk:vm-1:0", "disk nearly full")],
            checks_performed=[_SUBMAN_LABEL, _DISK_LABEL],
            checks_finding_counts={_DISK_LABEL: 1},
        ),
    }

    merged = merge_recollection(original, new_results)

    raw_refs = {ev.raw_ref for ev in merged.timeline}
    assert "guest:subman:vm-1:0" not in raw_refs  # the stale subman event is gone
    assert "guest:disk:vm-1:0" in raw_refs  # the fresh disk-usage event survived
    assert "resourcegraph:install:vm-1" in raw_refs  # untouched source's event survived


def test_a_non_recollected_sources_data_is_completely_untouched():
    original = _original()
    new_results = {
        Source.GUEST_LINUX: CollectionResult(events=[], checks_performed=[_SUBMAN_LABEL, _DISK_LABEL]),
    }

    merged = merge_recollection(original, new_results)

    assert merged.checks_finding_counts[_CONTROL_PLANE_LABEL] == 1
    assert Source.AZURE_CONTROL_PLANE in merged.sources_succeeded
    assert any(ev.raw_ref == "resourcegraph:install:vm-1" for ev in merged.timeline)


def test_a_source_that_succeeds_on_retry_clears_its_old_collection_gap():
    original = _original()
    new_results = {Source.GUEST_LINUX: CollectionResult(events=[])}

    merged = merge_recollection(original, new_results)

    assert merged.collection_gaps == []
    assert Source.GUEST_LINUX in merged.sources_succeeded


def test_a_source_that_fails_again_on_retry_keeps_the_original_gap_and_adds_the_fresh_one():
    """An errored retry doesn't supersede anything (see the "errored
    retry" docstring paragraph) - the original gap is left exactly as it
    was, and the fresh failure is recorded as its own, separate note."""
    original = _original()
    new_results = {Source.GUEST_LINUX: CollectionResult(events=[], error="Run Command timed out after 180s")}

    merged = merge_recollection(original, new_results)

    assert merged.collection_gaps == [
        "guest_linux: Run Command timed out after 60s",
        "guest_linux: recollection attempt failed: Run Command timed out after 180s",
    ]
    assert Source.GUEST_LINUX not in merged.sources_succeeded


def test_an_unrelated_sources_transient_recollection_failure_does_not_wipe_its_prior_good_evidence():
    """Found by review 2026-10-19: recollect_targeted() blasts EVERY
    applicable collector on every recollection pass, not just the one
    named in missing_evidence - so a recollection triggered by a
    guest_windows evidence gap also re-dispatches azure_control_plane,
    azure_monitor, and datadog. A first version of this function treated
    every key in new_results as superseding, unconditionally - so a
    transient, unrelated failure (a 429, a timeout) on a source that had
    ALREADY succeeded in the original pass wiped that source's real,
    already-persisted evidence. This is strictly worse than the bug this
    whole function exists to fix (which could never touch the DB)."""
    original = _original()  # azure_control_plane already has a real finding
    new_results = {
        Source.AZURE_CONTROL_PLANE: CollectionResult(events=[], error="429 Too Many Requests"),  # unrelated hiccup
        Source.GUEST_LINUX: CollectionResult(events=[]),  # the actually-targeted source, succeeds cleanly
    }

    merged = merge_recollection(original, new_results)

    assert merged.checks_finding_counts[_CONTROL_PLANE_LABEL] == 1  # the real finding survives
    assert any(ev.raw_ref == "resourcegraph:install:vm-1" for ev in merged.timeline)  # the real event survives
    assert Source.AZURE_CONTROL_PLANE in merged.sources_succeeded  # its original success is untouched
    assert "azure_control_plane: recollection attempt failed: 429 Too Many Requests" in merged.collection_gaps


def test_checks_performed_and_unavailable_are_replaced_per_recollected_source():
    original = _original()
    original = original.model_copy(update={"checks_unavailable": ["dpkg lock holder"]})
    new_results = {
        Source.GUEST_LINUX: CollectionResult(
            events=[], checks_performed=[_DISK_LABEL], checks_unavailable=[],  # fuser now found available
        ),
    }

    merged = merge_recollection(original, new_results)

    assert merged.checks_performed == [_DISK_LABEL]
    assert merged.checks_unavailable == []


def test_patch_extension_status_is_replaced_even_when_the_fresh_value_is_empty():
    """A naive `if result.patch_extension_status:` guard would silently
    keep a stale non-empty value just because the fresh pass legitimately
    found none this time - this is the same stale-data bug class as the
    finding-counts case, for a different field."""
    original = _original().model_copy(update={"patch_extension_status": [{"status": "Error", "code": "0x1"}]})
    new_results = {Source.GUEST_LINUX: CollectionResult(events=[], patch_extension_status=[])}

    merged = merge_recollection(original, new_results)

    assert merged.patch_extension_status == []


def test_a_fresh_outcome_replaces_the_original_one():
    original = _original()
    fresh_outcome = PatchOutcome(status="Succeeded")
    new_results = {Source.AZURE_CONTROL_PLANE: CollectionResult(events=[], outcome=fresh_outcome)}

    merged = merge_recollection(original, new_results)

    assert merged.outcome.status == "Succeeded"


def test_event_sources_for_expands_datadogs_one_dispatch_key_to_all_three():
    assert set(event_sources_for(Source.DATADOG_METRIC)) == {
        Source.DATADOG_METRIC, Source.DATADOG_MONITOR, Source.DATADOG_LOG,
    }


def test_event_sources_for_defaults_to_just_the_dispatch_key_itself():
    for source in (Source.GUEST_LINUX, Source.GUEST_WINDOWS, Source.AZURE_CONTROL_PLANE, Source.AZURE_MONITOR):
        assert event_sources_for(source) == (source,)


def test_a_datadog_recollection_drops_stale_monitor_and_log_events_too():
    """Found by review 2026-10-19: datadog_collector.py is registered under
    the single dispatch key Source.DATADOG_METRIC, but its one collect()
    call tags events with three different Source values - DATADOG_METRIC
    (metrics), DATADOG_MONITOR (monitor state), DATADOG_LOG (post-reboot
    logs). Filtering the timeline by the bare dispatch key alone left a
    stale, since-resolved monitor alert (or log finding) behind whenever a
    fresh recollection pass didn't reproduce it - the same "additive, not
    replaced" bug this whole function exists to avoid, just for one
    collector's secondary event types."""
    original = _original().model_copy(update={
        "timeline": [
            _event(Source.DATADOG_MONITOR, "monitor_transition", "datadog:monitor:1", "disk monitor: Alert"),
            _event(Source.DATADOG_LOG, "log_line", "datadog:log:1", "reboot error"),
        ],
        "sources_attempted": [Source.DATADOG_METRIC],
        "sources_succeeded": [Source.DATADOG_METRIC],
    })
    # The fresh recollection pass found a clean state - no monitor alert,
    # no log line - but did find a metric point.
    new_results = {
        Source.DATADOG_METRIC: CollectionResult(
            events=[_event(Source.DATADOG_METRIC, "metric_point", "datadog:metric:1", "disk.free_pct = 42")],
        ),
    }

    merged = merge_recollection(original, new_results)

    raw_refs = {ev.raw_ref for ev in merged.timeline}
    assert raw_refs == {"datadog:metric:1"}  # both stale events gone, fresh one present


def test_an_identical_re_fetched_event_is_not_duplicated():
    original = _original()
    new_results = {
        Source.AZURE_CONTROL_PLANE: CollectionResult(
            events=[_event(Source.AZURE_CONTROL_PLANE, "patch_install_result", "resourcegraph:install:vm-1")],
        ),
    }

    merged = merge_recollection(original, new_results)

    matching = [ev for ev in merged.timeline if ev.raw_ref == "resourcegraph:install:vm-1"]
    assert len(matching) == 1
