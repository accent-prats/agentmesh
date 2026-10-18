"""Turns a cluster's (or machine's) raw `collection_gaps`/`missing_evidence`
strings into structured, display-ready items.

Every one of these strings originates from pipeline/normalize.py's
`merge_bundle()`, which always writes them as "{source.value}: {error}" -
one per collector that failed (see that function's own docstring). The
deep RCA agent (pipeline/rca_agent.py) either echoes these verbatim into
its own `missing_evidence` output or writes a handful of agent-authored
reasons that carry no source prefix at all (e.g. "Deep RCA agent not
configured for this pipeline run") - both shapes are handled here, the
source-prefixed ones just get the richer treatment (icon, friendly label,
a best-effort correlation ID pulled out for a support ticket).

This is a pure, display-time transform - it never changes what the RCA
agent is asked to produce or what gets persisted, so it's safe to extend
without touching the model's schema or the pipeline at all."""
from __future__ import annotations

import re
from dataclasses import dataclass

from culprit.models.evidence import Source
from culprit.models.rca import split_unverifiable_reason

_SOURCE_PREFIX_RE = re.compile(r"^(" + "|".join(re.escape(s.value) for s in Source) + r"):\s*(.*)$", re.DOTALL)
_CORRELATION_ID_RE = re.compile(r"correlationId\s*=\s*([^\s,;]+)", re.IGNORECASE)
_SUMMARY_MAX_CHARS = 140

# (friendly label, lucide icon name) - deliberately not just `source.value`
# title-cased: "azure_control_plane" means nothing to a reviewer, "Azure
# Resource Graph" does.
_SOURCE_DISPLAY: dict[Source, tuple[str, str]] = {
    Source.AZURE_CONTROL_PLANE: ("Azure Resource Graph", "cloud"),
    Source.AZURE_MONITOR: ("Azure Monitor", "activity"),
    Source.GUEST_WINDOWS: ("Windows guest agent", "monitor"),
    Source.GUEST_LINUX: ("Linux guest agent", "terminal"),
    Source.DATADOG_METRIC: ("Datadog metrics", "bar-chart-2"),
    Source.DATADOG_MONITOR: ("Datadog monitor", "bell"),
    Source.DATADOG_LOG: ("Datadog logs", "file-text"),
    Source.DATADOG_EVENT: ("Datadog events", "radio"),
}
_GENERIC_LABEL, _GENERIC_ICON = "Evidence gap", "alert-triangle"
# Distinct from a genuine "couldn't collect this source" gap - this is the
# pipeline itself rejecting the model's output (see models/rca.py's
# format_unverifiable_reason). A different icon/label makes clear this
# isn't a missing log file, it's an analysis that didn't hold up.
_UNVERIFIABLE_LABEL, _UNVERIFIABLE_ICON = "Unverified analysis", "shield-alert"


@dataclass(frozen=True)
class EvidenceGap:
    label: str
    icon: str
    summary: str
    # None when the message already fit on one line - lets the template
    # skip rendering an expand toggle that would reveal nothing new.
    detail: str | None
    correlation_id: str | None


def _summarize(message: str) -> tuple[str, str | None]:
    flat = " ".join(message.split())
    if len(flat) <= _SUMMARY_MAX_CHARS:
        return flat, None
    cut = flat[:_SUMMARY_MAX_CHARS].rsplit(" ", 1)[0]
    # A word-boundary cut can land almost immediately when the message is a
    # short lead word followed by one long unbroken token (a URL, a hash,
    # base64) - showing a near-empty summary instead of one that actually
    # uses the available budget. Fall back to a hard cut once the word
    # boundary would throw away more than ~20% of it.
    if len(cut) < _SUMMARY_MAX_CHARS * 0.8:
        cut = flat[:_SUMMARY_MAX_CHARS]
    return f"{cut}…", flat


def parse_evidence_gaps(items: list[str]) -> list[EvidenceGap]:
    gaps = []
    for item in items:
        unverifiable = split_unverifiable_reason(item)
        if unverifiable is not None:
            # Always keep the raw technical reason behind the expand
            # toggle, even when it's short enough to fit as the headline
            # on its own merits - unlike _summarize() below, this one is
            # deliberately never shown as the primary text, since it's an
            # internal rejection reason, not a human-authored summary.
            summary, raw_detail = unverifiable
            gaps.append(EvidenceGap(
                label=_UNVERIFIABLE_LABEL, icon=_UNVERIFIABLE_ICON,
                summary=summary.strip(), detail=raw_detail.strip() or None,
                correlation_id=None,
            ))
            continue

        match = _SOURCE_PREFIX_RE.match(item)
        if match:
            label, icon = _SOURCE_DISPLAY[Source(match.group(1))]
            message = match.group(2).strip()
        else:
            label, icon = _GENERIC_LABEL, _GENERIC_ICON
            message = item.strip()

        summary, detail = _summarize(message)
        correlation_match = _CORRELATION_ID_RE.search(message)
        gaps.append(EvidenceGap(
            label=label, icon=icon, summary=summary, detail=detail,
            correlation_id=correlation_match.group(1).rstrip(".,;") if correlation_match else None,
        ))
    return gaps
