"""reporting/evidence_timeline_view.py - display-only view over a
persisted, already-structured MachineOutcomeRecord.timeline_json list, the
same shape of coverage test_evidence_gaps.py gives evidence_gaps.py."""
from __future__ import annotations

from datetime import datetime, timezone

from culprit.reporting.evidence_timeline_view import build_timeline_views


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
