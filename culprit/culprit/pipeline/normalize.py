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

from culprit.collectors.base import CollectionResult
from culprit.models.evidence import EvidenceBundle, MachineIdentity, PatchOutcome, Source


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

    for source_key, result in results.items():
        source = source_key if isinstance(source_key, Source) else _coerce_source(source_key)
        attempted.append(source)
        if result.error:
            gaps.append(f"{source.value}: {result.error}")
        else:
            succeeded.append(source)
        events.extend(result.events)
        patch_extension_status.extend(result.patch_extension_status)
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
    )


def _coerce_source(name: str) -> Source:
    aliases = {
        "azure_control_plane": Source.AZURE_CONTROL_PLANE,
        "azure_monitor": Source.AZURE_MONITOR,
        "guest_windows": Source.GUEST_WINDOWS,
        "guest_linux": Source.GUEST_LINUX,
        "datadog": Source.DATADOG_METRIC,
    }
    return aliases.get(name, Source.AZURE_CONTROL_PLANE)
