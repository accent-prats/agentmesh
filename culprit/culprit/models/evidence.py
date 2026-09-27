"""Evidence domain models.

An EvidenceBundle is the normalised, per-machine output of the collection
stage: every signal collectors pulled from Azure, the guest OS, and Datadog,
merged into one chronological timeline. Nothing downstream (fingerprinting,
rules, the RCA agent) ever touches a raw collector payload directly - it
only ever sees an EvidenceBundle. That's the seam that keeps the rest of
the pipeline collector-agnostic.
"""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Source(str, enum.Enum):
    """Which of the four evidence planes a signal came from."""

    AZURE_CONTROL_PLANE = "azure_control_plane"   # Resource Graph, Maintenance, Activity Log
    AZURE_MONITOR = "azure_monitor"                 # Log Analytics (Heartbeat/Event/Syslog)
    GUEST_WINDOWS = "guest_windows"                  # Run Command on a Windows VM
    GUEST_LINUX = "guest_linux"                      # Run Command on a Linux VM
    DATADOG_METRIC = "datadog_metric"
    DATADOG_MONITOR = "datadog_monitor"
    DATADOG_LOG = "datadog_log"
    DATADOG_EVENT = "datadog_event"


class OSFamily(str, enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


class TimelineEvent(BaseModel):
    """One normalised, timestamped fact.

    `raw_ref` is the pointer back to the original collector payload (a blob
    storage key, a Log Analytics row id, a Datadog query + point index) so
    every claim the RCA agent makes can be traced to something concrete.
    This is what makes the "no citation, no claim" rule enforceable rather
    than aspirational.
    """

    ts: datetime
    source: Source
    kind: str = Field(..., description="e.g. 'metric_point', 'log_line', 'api_result', 'monitor_transition'")
    summary: str = Field(..., description="One-line, human-readable rendering of the event")
    detail: dict[str, Any] = Field(default_factory=dict)
    raw_ref: str = Field(..., description="Opaque pointer into the raw evidence store for this event")


class MachineIdentity(BaseModel):
    vm_id: str = Field(..., description="Azure resource ID")
    vm_name: str
    resource_group: str
    subscription_id: str
    os_family: OSFamily
    os_version: str | None = None
    is_arc_connected: bool = False
    tags: dict[str, str] = Field(default_factory=dict)


class PatchOutcome(BaseModel):
    """The Azure Update Manager verdict for one machine in one run - the
    thing everyone currently starts and stops their investigation at."""

    status: str = Field(..., description="Succeeded | Failed | CompletedWithWarnings | ...")
    error_code: str | None = None
    error_message: str | None = None
    packages_installed: list[str] = Field(default_factory=list)
    packages_failed: list[str] = Field(default_factory=list)
    kbs_installed: list[str] = Field(default_factory=list)
    kbs_failed: list[str] = Field(default_factory=list)
    reboot_status: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    window_minutes: int | None = None


class EvidenceBundle(BaseModel):
    """Everything collected about one machine's participation in one patch run."""

    run_id: str
    machine: MachineIdentity
    outcome: PatchOutcome
    timeline: list[TimelineEvent] = Field(default_factory=list)
    collection_started_at: datetime
    collection_completed_at: datetime | None = None
    sources_attempted: list[Source] = Field(default_factory=list)
    sources_succeeded: list[Source] = Field(default_factory=list)
    collection_gaps: list[str] = Field(
        default_factory=list,
        description="Human-readable notes on evidence that could not be collected, e.g. "
        "'guest Run Command timed out' or 'Datadog agent not reporting'.",
    )

    def timeline_sorted(self) -> list[TimelineEvent]:
        return sorted(self.timeline, key=lambda e: e.ts)

    def events_from(self, source: Source) -> list[TimelineEvent]:
        return [e for e in self.timeline if e.source == source]

    def render_timeline_text(self) -> str:
        """Render the timeline as compact text - this is what gets fed to
        the RCA agent's prompt. The UI shows this machine's `PatchOutcome`
        summary (see MachineOutcomeRecord, `/runs/{run_id}/machines/{vm_name}.html`),
        not the raw timeline this renders - that stays evidence for the
        model's reasoning, not something a reviewer reads directly today."""
        lines = []
        t0 = self.outcome.started_at or (self.timeline_sorted()[0].ts if self.timeline else None)
        for ev in self.timeline_sorted():
            offset = f"T{'+' if not t0 or ev.ts >= t0 else '-'}{abs((ev.ts - t0).total_seconds() / 3600):.1f}h" if t0 else ev.ts.isoformat()
            lines.append(f"[{offset}] {ev.source.value:<22} {ev.summary}  ({ev.raw_ref})")
        return "\n".join(lines)
