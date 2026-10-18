"""Display-only view over `MachineOutcomeRecord.timeline_json` - the
capped, persisted slice of `EvidenceBundle.timeline` (models/evidence.py::
TimelineEvent) saved by `db/repository.py::save_machine_outcomes`, for the
machine drill-down page's "Evidence timeline" card. Like
extension_status_view.py, this is presentation logic over already-
structured data, not another parsing pass.

Deliberately shows the same five fields the RCA agent itself reasons from
(ts, source, summary, raw_ref - models/evidence.py::
EvidenceBundle.render_timeline_text() never sends `detail` to the LLM
either, see ARCHITECTURE.md) - this card is honest about showing exactly
what evidence the model saw, not a richer view invented for humans only."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

_SOURCE_DISPLAY: dict[str, tuple[str, str]] = {  # source value -> (label, icon)
    "azure_control_plane": ("Azure control plane", "cloud"),
    "azure_monitor": ("Azure Monitor", "activity"),
    "guest_windows": ("Guest (Windows)", "terminal"),
    "guest_linux": ("Guest (Linux)", "terminal"),
    "datadog_metric": ("Datadog (metric)", "bar-chart-2"),
    "datadog_monitor": ("Datadog (monitor)", "bar-chart-2"),
    "datadog_log": ("Datadog (log)", "bar-chart-2"),
    "datadog_event": ("Datadog (event)", "bar-chart-2"),
}
_DEFAULT_DISPLAY = ("Unknown source", "circle")


@dataclass(frozen=True)
class TimelineEventView:
    ts: datetime
    source_label: str
    icon: str
    summary: str
    raw_ref: str


def build_timeline_views(timeline: list[dict]) -> list[TimelineEventView]:
    """Sorted chronologically (oldest first), matching
    EvidenceBundle.render_timeline_text()'s own ordering - the same
    narrative sequence the RCA agent itself read. Defensive against a
    malformed/legacy entry the same way build_extension_finding_views is:
    a missing/unparseable field degrades to a safe default, never raises."""
    views = []
    for event in timeline:
        if not isinstance(event, dict):
            continue
        label, icon = _SOURCE_DISPLAY.get(event.get("source"), _DEFAULT_DISPLAY)
        views.append(TimelineEventView(
            ts=_parse_ts(event.get("ts")),
            source_label=label, icon=icon,
            summary=event.get("summary") or "",
            raw_ref=event.get("raw_ref") or "",
        ))
    views.sort(key=lambda v: v.ts)
    return views


def _parse_ts(value: object) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)
