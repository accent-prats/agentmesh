"""Merge per-source CollectionResults into one EvidenceBundle.

This is the seam between "four different APIs with four different
shapes" and "one unified timeline" that the rest of the pipeline reasons
over. It does three real things, not just concatenation:

  1. Sorts every event into one chronological timeline.
  2. Picks the PatchOutcome from whichever collector produced one (only
     the control-plane collector does).
  3. Turns a collector's `error` into a `collection_gaps` note, so a
     missing source is visible to the RCA agent and the report instead of
     silently vanishing.
"""
from __future__ import annotations

from datetime import datetime, timezone

from culprit.collectors.base import NON_GUEST_LOG_LABELS, CollectionResult, event_sources_for
from culprit.models.evidence import EvidenceBundle, MachineIdentity, PatchOutcome, Source, TimelineEvent


def merge_bundle(
    run_id: str,
    machine: MachineIdentity,
    results: dict[Source | str, CollectionResult],
    collection_started_at: datetime | None = None,
) -> EvidenceBundle:
    events = []
    outcome: PatchOutcome | None = None
    gaps: list[str] = []
    attempted: list[Source] = []
    succeeded: list[Source] = []
    patch_extension_status: list[dict] = []
    checks_performed: list[str] = []
    checks_unavailable: list[str] = []
    checks_finding_counts: dict[str, int] = {}

    for source_key, result in results.items():
        source = source_key if isinstance(source_key, Source) else _coerce_source(source_key)
        attempted.append(source)
        if result.error:
            gaps.append(f"{source.value}: {result.error}")
        else:
            succeeded.append(source)
        events.extend(result.events)
        patch_extension_status.extend(result.patch_extension_status)
        checks_performed.extend(result.checks_performed)
        checks_unavailable.extend(result.checks_unavailable)
        for label, count in result.checks_finding_counts.items():
            checks_finding_counts[label] = checks_finding_counts.get(label, 0) + count
        if result.outcome is not None:
            outcome = result.outcome

    if outcome is None:
        # No control-plane collector succeeded - synthesize a placeholder
        # so downstream code never has to null-check `bundle.outcome`.
        outcome = PatchOutcome(status="Unknown", error_message="Control-plane collector did not return an outcome")
        gaps.append("azure_control_plane: no patch outcome available")

    # Stable de-dup: identical (ts, source, kind, raw_ref) can legitimately
    # occur when a targeted second collection pass re-fetches a signal that
    # was already present - keep the first occurrence.
    seen = set()
    deduped = []
    for ev in sorted(events, key=lambda e: e.ts):
        key = (ev.ts, ev.source, ev.kind, ev.raw_ref)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ev)

    return EvidenceBundle(
        run_id=run_id,
        machine=machine,
        outcome=outcome,
        timeline=deduped,
        collection_started_at=collection_started_at or datetime.now(timezone.utc),
        collection_completed_at=datetime.now(timezone.utc),
        sources_attempted=attempted,
        sources_succeeded=succeeded,
        collection_gaps=gaps,
        patch_extension_status=patch_extension_status,
        checks_performed=checks_performed,
        checks_unavailable=checks_unavailable,
        checks_finding_counts=checks_finding_counts,
    )


def _label_owners() -> dict[str, Source]:
    """Which Source each checks_performed/checks_unavailable/checks_finding_
    counts label belongs to - built from the same canonical sources
    (GuestLogSource tuples, NON_GUEST_LOG_LABELS) the collectors and
    reporting/log_usage_view.py already key off of, so this can never drift
    out of sync with them. Imported lazily (not at module level) purely to
    avoid a real import cycle risk: guest_linux.py/guest_windows.py sit one
    layer below pipeline/ in this codebase's dependency direction, and
    nothing here needs this map at import time - only when a recollection
    actually needs merging, which is comparatively rare."""
    from culprit.collectors.guest_linux import GUEST_LOG_SOURCES as linux_sources
    from culprit.collectors.guest_windows import GUEST_LOG_SOURCES as windows_sources

    owners: dict[str, Source] = {label: source for source, label in NON_GUEST_LOG_LABELS.items()}
    for gls in linux_sources:
        owners[gls.label] = Source.GUEST_LINUX
    for gls in windows_sources:
        owners[gls.label] = Source.GUEST_WINDOWS
    return owners


def merge_recollection(original: EvidenceBundle, new_results: dict[Source, CollectionResult]) -> EvidenceBundle:
    """Re-merge a targeted recollection pass's fresh per-source results into
    an already-merged EvidenceBundle.

    Unlike merge_bundle() (which builds a bundle from scratch out of every
    source's first CollectionResult), this starts from an EvidenceBundle
    that has already discarded its own per-source CollectionResults - by
    the time pipeline/orchestrator.py's recollection pass runs, the first
    merge_bundle() call has already collapsed them into one flattened
    bundle, so there is nothing left to splice the new per-source results
    into via merge_bundle() itself.

    recollect_targeted() always re-runs EVERY applicable collector for a
    machine fully, not incrementally - confirmed directly: guest_linux.py/
    guest_windows.py run the identical fixed script regardless of
    `request.only` (it only ever changes the Run Command timeout), and
    azure_control_plane.py's collect() doesn't filter its queries by it
    either. So a source that SUCCEEDS in `new_results` fully supersedes
    whatever that same source contributed to `original`, for EVERY
    per-source field - including `timeline`, not just the summary fields
    (a source whose fresh attempt errored is handled differently - see the
    "errored retry" paragraph below). A first-draft
    version of this function treated `timeline` as purely additive (keep
    every old event, append new ones, dedup by exact key) on the theory
    that evidence is only ever gained, never lost - but that's inconsistent
    the moment a recollected source's checks_finding_counts legitimately
    drops a label it reported before (a flaky first-pass finding that
    doesn't reproduce on a clean, longer-timeout retry): the model's prompt
    would still carry a TimelineEvent describing a finding that
    checks_finding_counts now says didn't happen. Treating every field the
    same way - full replacement of a recollected source's contribution -
    keeps the bundle internally consistent.

    Found 2026-10-19 from a real production run (tcx-tenant): without this,
    a targeted recollection that genuinely recovered real guest data on its
    retry still left the machine page showing every guest check as "not
    collected" - indistinguishable from the retry having found nothing -
    because save_machine_outcomes() only ever persisted the pre-
    recollection bundle; the recollected events only ever reached the RCA
    agent's own second-pass prompt, never the UI or the DB.

    Only a source whose fresh attempt actually SUCCEEDED replaces its prior
    contribution - found by review 2026-10-19: recollect_targeted() blasts
    EVERY applicable collector on every recollection pass, not just the one
    named in missing_evidence (e.g. a gap about guest_windows evidence
    still re-dispatches azure_control_plane/azure_monitor/datadog too). A
    first version of this function treated every key in `new_results` as
    superseding, unconditionally - so an unrelated, transient failure
    (a 429, a timeout) on a source that had ALREADY succeeded in the
    original pass would wipe that source's real, already-persisted
    evidence and replace it with nothing plus a fresh error note. An
    errored retry proves nothing about whether the original finding is
    still true, so it must leave that source's prior contribution alone
    entirely - this is strictly worse than the pre-fix bug (which could at
    worst leave the second RCA prompt slightly thinner, but could never
    corrupt the DB) if left unhandled."""
    owners = _label_owners()
    # Only a source that actually succeeded this pass gets to replace its
    # prior contribution - see the docstring's "errored retry" paragraph.
    # `recollected` (every attempted source, success or not) is still used
    # below for `sources_attempted` and to decide whether to append a FRESH
    # collection_gaps note, since an attempt - successful or not - is still
    # worth recording as having happened.
    recollected = set(new_results.keys())
    superseding = {s for s, r in new_results.items() if not r.error}

    def _owned_by_superseding(label: str) -> bool:
        return owners.get(label) in superseding

    gaps = [g for g in original.collection_gaps if not any(g.startswith(f"{s.value}:") for s in superseding)]
    attempted = set(original.sources_attempted) | recollected
    succeeded = set(original.sources_succeeded) - superseding
    # Only guest_linux.py/guest_windows.py ever populate patch_extension_
    # status, and a machine only ever has one applicable guest source - if
    # that source's fresh attempt succeeded, its (possibly now-empty) value
    # must fully replace the original's, the same as every other field
    # below. Checking membership rather than `if result.patch_extension_
    # status:` specifically avoids silently keeping a stale, non-empty
    # value just because the fresh pass legitimately found none.
    patch_extension_status = original.patch_extension_status
    outcome = original.outcome
    checks_performed = {c for c in original.checks_performed if not _owned_by_superseding(c)}
    checks_unavailable = {c for c in original.checks_unavailable if not _owned_by_superseding(c)}
    checks_finding_counts = {k: v for k, v in original.checks_finding_counts.items() if not _owned_by_superseding(k)}
    # A recollected dispatch key isn't always the only Source value that
    # collector's own events carry (datadog_collector.py is registered
    # under the single key DATADOG_METRIC but tags events with
    # DATADOG_METRIC/DATADOG_MONITOR/DATADOG_LOG - see collectors/base.py::
    # DISPATCH_KEY_EVENT_SOURCES's own comment for why) - found by review
    # 2026-10-19: filtering by the bare dispatch key alone left a stale
    # Datadog monitor/log event behind whenever the fresh recollection
    # pass didn't reproduce it, the same "additive, not replaced" bug this
    # whole function exists to avoid, just for one collector's secondary
    # event types.
    superseding_event_sources = {es for key in superseding for es in event_sources_for(key)}
    timeline = [ev for ev in original.timeline if ev.source not in superseding_event_sources]

    new_events: list[TimelineEvent] = []
    for source, result in new_results.items():
        if result.error:
            # Deliberately does not touch gaps/checks_*/timeline/patch_
            # extension_status/outcome for this source at all - see the
            # docstring. A fresh error is still worth recording as its own
            # note (distinct from the original's gap, if any, which is
            # left untouched above) so an operator can see the retry itself
            # also failed, without it looking like evidence vanished.
            gaps.append(f"{source.value}: recollection attempt failed: {result.error}")
            continue
        succeeded.add(source)
        new_events.extend(result.events)
        if source in (Source.GUEST_LINUX, Source.GUEST_WINDOWS):
            patch_extension_status = result.patch_extension_status
        if result.outcome is not None:
            outcome = result.outcome
        checks_performed |= set(result.checks_performed)
        checks_unavailable |= set(result.checks_unavailable)
        checks_finding_counts.update(result.checks_finding_counts)

    # Defensive, not load-bearing today (timeline is already fully replaced
    # per recollected source above, so a key collision would only happen if
    # a single collector's own `collect()` returned a genuine internal
    # duplicate) - cheap insurance against a double-counted event either
    # way, same dedup key merge_bundle() itself uses.
    seen = {(ev.ts, ev.source, ev.kind, ev.raw_ref) for ev in timeline}
    deduped_new = []
    for ev in new_events:
        key = (ev.ts, ev.source, ev.kind, ev.raw_ref)
        if key in seen:
            continue
        seen.add(key)
        deduped_new.append(ev)

    return original.model_copy(update={
        "timeline": timeline + deduped_new,
        "outcome": outcome,
        "sources_attempted": sorted(attempted, key=lambda s: s.value),
        "sources_succeeded": sorted(succeeded, key=lambda s: s.value),
        "collection_gaps": gaps,
        "patch_extension_status": patch_extension_status,
        "checks_performed": sorted(checks_performed),
        "checks_unavailable": sorted(checks_unavailable),
        "checks_finding_counts": checks_finding_counts,
    })


def _coerce_source(name: str) -> Source:
    aliases = {
        "azure_control_plane": Source.AZURE_CONTROL_PLANE,
        "azure_monitor": Source.AZURE_MONITOR,
        "guest_windows": Source.GUEST_WINDOWS,
        "guest_linux": Source.GUEST_LINUX,
        "datadog": Source.DATADOG_METRIC,
    }
    return aliases.get(name, Source.AZURE_CONTROL_PLANE)
