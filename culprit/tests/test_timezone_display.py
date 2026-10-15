"""reporting/timezone_display.py - the admin-configurable display
timezone conversion (models/settings.py::DisplayTimezoneSettingsInput).
Every datetime stays stored in UTC regardless; this only affects display.

The localize_date tests are the actual regression this whole feature was
partly about: the cluster date-range label and the console trend chart
(reporting/render.py::_cluster_date_ranges/_trend_chart_geometry) used to
derive a calendar date straight from the raw UTC instant - a patch that
ran at 2026-10-14 21:33 UTC is 2026-10-15 03:03 IST, a *different*
calendar day, which only localize_date (not the old plain .date() call)
gets right."""
from __future__ import annotations

from datetime import datetime, timezone

import jinja2

from culprit.reporting.timezone_display import localize_date, register_localtime_filter


def test_localtime_filter_passes_through_unchanged_under_utc():
    env = jinja2.Environment()
    register_localtime_filter(env, "UTC")
    dt = datetime(2026, 10, 14, 21, 33, tzinfo=timezone.utc)
    assert env.filters["localtime"](dt) == "2026-10-14 21:33 UTC"


def test_localtime_filter_converts_to_ist_with_the_correct_abbreviation():
    env = jinja2.Environment()
    register_localtime_filter(env, "Asia/Kolkata")
    dt = datetime(2026, 10, 14, 21, 33, tzinfo=timezone.utc)
    assert env.filters["localtime"](dt) == "2026-10-15 03:03 IST"


def test_localtime_filter_handles_a_naive_datetime_as_utc():
    """MachineOutcomeRecord.started_at round-trips through SQLite as a
    naive datetime (no tzinfo) - must still be treated as UTC, not
    misinterpreted as already being in the local zone."""
    env = jinja2.Environment()
    register_localtime_filter(env, "Asia/Kolkata")
    naive = datetime(2026, 10, 14, 21, 33)
    assert env.filters["localtime"](naive) == "2026-10-15 03:03 IST"


def test_localtime_filter_accepts_a_custom_format_string():
    env = jinja2.Environment()
    register_localtime_filter(env, "Asia/Kolkata")
    dt = datetime(2026, 10, 14, 21, 33, tzinfo=timezone.utc)
    assert env.filters["localtime"](dt, "%H:%M") == "03:03 IST"


def test_localtime_filter_returns_empty_string_for_none():
    env = jinja2.Environment()
    register_localtime_filter(env, "UTC")
    assert env.filters["localtime"](None) == ""


def test_localize_date_stays_on_the_same_day_under_utc():
    dt = datetime(2026, 10, 14, 21, 33, tzinfo=timezone.utc)
    assert localize_date(dt, "UTC").isoformat() == "2026-10-14"


def test_localize_date_crosses_the_calendar_boundary_under_ist():
    """The actual regression guard: 21:33 UTC is 03:03 the *next* day in
    IST (UTC+5:30) - localize_date must reflect that, not silently keep
    the UTC date."""
    dt = datetime(2026, 10, 14, 21, 33, tzinfo=timezone.utc)
    assert localize_date(dt, "Asia/Kolkata").isoformat() == "2026-10-15"


def test_localize_date_returns_none_for_none():
    assert localize_date(None, "Asia/Kolkata") is None
