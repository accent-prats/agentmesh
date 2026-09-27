"""Fan-out collection: run every configured collector against every
machine in a patch run, in parallel, and merge each machine's results into
one EvidenceBundle (proposal Section 4, "Collect" step).

Kept separate from the orchestrator so the orchestrator itself can be
exercised in tests against pre-built EvidenceBundles (e.g. from
culprit/demo/generate_scenario.py) without needing live collectors wired
up - the orchestrator doesn't know or care whether a bundle came from here
or from a fixture.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from culprit.collectors.base import CollectionRequest, Collector
from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, Source
from culprit.pipeline.normalize import merge_bundle

log = logging.getLogger(__name__)

# guest_linux/guest_windows are each built for exactly one OS - running the
# wrong one against a machine wouldn't corrupt anything (Run Command would
# just fail and collection.py already turns that into a harmless
# collection_gaps note), but it wastes an API call and a Run Command
# invocation on every single machine, every single run. Skip it instead.
_OS_SPECIFIC_SOURCES: dict[Source, OSFamily] = {
    Source.GUEST_LINUX: OSFamily.LINUX,
    Source.GUEST_WINDOWS: OSFamily.WINDOWS,
}


def _applies_to(source: Source, machine: MachineIdentity) -> bool:
    required_os = _OS_SPECIFIC_SOURCES.get(source)
    return required_os is None or machine.os_family == required_os


def collect_all(
    run_id: str,
    machines: list[MachineIdentity],
    collectors: dict[Source, Collector],
    window_start: datetime,
    window_end: datetime,
    max_workers: int = 8,
) -> list[EvidenceBundle]:
    def collect_one(machine: MachineIdentity) -> EvidenceBundle:
        request = CollectionRequest(machine=machine, window_start=window_start, window_end=window_end, run_id=run_id)
        results = {}
        for source, collector in collectors.items():
            if not _applies_to(source, machine):
                continue
            try:
                results[source] = collector.collect(request)
            except Exception as exc:  # noqa: BLE001 - one collector's crash must not sink the machine
                log.exception("Collector %s failed for %s", source, machine.vm_id)
                from culprit.collectors.base import CollectionResult

                results[source] = CollectionResult(events=[], error=str(exc))
        return merge_bundle(run_id, machine, results, collection_started_at=window_start)

    bundles: list[EvidenceBundle] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(collect_one, m): m for m in machines}
        for future in as_completed(futures):
            bundles.append(future.result())
    return bundles


def recollect_targeted(
    run_id: str,
    machine: MachineIdentity,
    missing_evidence: list[str],
    collectors: dict[Source, Collector],
    window_start: datetime,
    window_end: datetime,
) -> list:
    """The re-dispatch path: when the RCA agent names specific
    `missing_evidence`, fetch exactly that rather than re-running every
    collector from scratch (proposal Section 4: "two targeted passes beat
    one speculative one")."""
    request = CollectionRequest(
        machine=machine, window_start=window_start, window_end=window_end, run_id=run_id, only=missing_evidence
    )
    events = []
    for source, collector in collectors.items():
        if not _applies_to(source, machine):
            continue
        try:
            result = collector.collect(request)
            events.extend(result.events)
        except Exception:  # noqa: BLE001
            log.exception("Targeted recollection failed for %s / %s", machine.vm_id, source)
    return events
