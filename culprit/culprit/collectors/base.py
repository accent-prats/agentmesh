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

from culprit.models.evidence import MachineIdentity, PatchOutcome, TimelineEvent


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


class Collector(abc.ABC):
    source_name: str

    @abc.abstractmethod
    def collect(self, request: CollectionRequest) -> CollectionResult:
        ...
