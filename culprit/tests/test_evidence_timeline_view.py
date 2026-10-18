"""reporting/evidence_timeline_view.py - display-only view over a
persisted, already-structured MachineOutcomeRecord.timeline_json list, the
same shape of coverage test_evidence_gaps.py gives evidence_gaps.py."""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

from culprit.reporting.evidence_timeline_view import TimelineEventView, build_timeline_views


def test_build_timeline_views_maps_a_known_source_to_its_label_and_icon():
    timeline = [{
        "ts": "2026-10-18T08:05:00+00:00", "source": "guest_linux", "kind": "repo_diagnostics",
        "summary": "Repo diagnostics for mirror.example.com: dns_resolved=False",
        "raw_ref": "guest:repo_diagnostics:vm-1",
    }]
    views = build_timeline_views(timeline)
    assert len(views) == 1
    assert views[0].source_label == "Guest (Linux)"
    assert views[0].icon == "terminal"
    assert views[0].summary == "Repo diagnostics for mirror.example.com: dns_resolved=False"
    assert views[0].raw_ref == "guest:repo_diagnostics:vm-1"
    assert views[0].ts == datetime(2026, 10, 18, 8, 5, tzinfo=timezone.utc)


def test_build_timeline_views_defaults_an_unknown_source():
    views = build_timeline_views([{"ts": "2026-10-18T08:00:00Z", "source": "some_future_source", "summary": "x", "raw_ref": "r"}])
    assert views[0].source_label == "Unknown source"
    assert views[0].icon == "circle"


def test_build_timeline_views_sorts_chronologically():
    timeline = [
        {"ts": "2026-10-18T09:00:00Z", "source": "guest_linux", "summary": "second", "raw_ref": "r2"},
        {"ts": "2026-10-18T08:00:00Z", "source": "guest_linux", "summary": "first", "raw_ref": "r1"},
    ]
    views = build_timeline_views(timeline)
    assert [v.summary for v in views] == ["first", "second"]


def test_build_timeline_views_is_defensive_against_malformed_entries():
    """A missing/unparseable field degrades to a safe default, never
    raises - same discipline as build_extension_finding_views."""
    views = build_timeline_views([
        "not a dict",
        {},
        {"ts": "not a timestamp", "source": "guest_linux", "summary": "x", "raw_ref": "r"},
    ])
    assert len(views) == 2  # the plain string entry is skipped, the two dicts survive
    assert views[0].summary == ""
    assert views[1].summary == "x"


def test_build_timeline_views_empty_input_is_silent():
    assert build_timeline_views([]) == []


def test_timeline_event_view_never_carries_the_richer_detail_dict():
    """Found in review 2026-10-18: nothing previously locked in the design
    claim that this card shows a human exactly what the RCA agent saw -
    render_timeline_text() (models/evidence.py) only ever sends
    ts/source/summary/raw_ref to the LLM, never `detail` (which can carry
    raw diagnostic payloads collectors attach for their own structured
    use, e.g. patch counts, full proxy/DNS probe output). A prior sabotage
    check added a `detail` field to TimelineEventView and populated it -
    every other test here still passed, because none of them assert the
    view's own shape, only its already-exposed fields' values. This
    structural check - the dataclass's field names, not just today's
    template not happening to reference one - is what actually prevents a
    future edit from silently widening what this page exposes."""
    field_names = {f.name for f in dataclasses.fields(TimelineEventView)}
    assert field_names == {"ts", "source_label", "icon", "summary", "raw_ref"}
