"""Converts a UTC-stored datetime to the admin-configured display
timezone (models/settings.py::DisplayTimezoneSettingsInput) for rendering
only - every datetime is collected and persisted in UTC regardless of
this setting; nothing here ever changes what's stored.

Found needed 2026-10-15: every report/console/email timestamp was always
shown in UTC with no conversion, and two places (_cluster_date_ranges,
_trend_chart_geometry in render.py) derived a *calendar date* directly
from the raw UTC instant - a patch that ran at 2026-10-14 21:33 UTC is
2026-10-15 03:03 IST, a different calendar day, so those two needed more
than a cosmetic format-string fix once a non-UTC display timezone exists."""
from __future__ import annotations

from datetime import date, datetime, timezone

from zoneinfo import ZoneInfo


def _as_aware_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def register_localtime_filter(env, tz_name: str) -> None:
    """Registers the `localtime` Jinja filter on `env`, closed over
    `tz_name` - env.py's _env() has no DB session of its own (see its own
    docstring on why promotion_threshold/promotion_min_sample are explicit
    params, not globals), so `tz_name` must come from the caller, not be
    looked up in here."""
    zone = ZoneInfo(tz_name)

    def localtime(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
        if dt is None:
            return ""
        localized = _as_aware_utc(dt).astimezone(zone)
        return f"{localized.strftime(fmt)} {localized.tzname()}"

    env.filters["localtime"] = localtime


def localize_date(dt: datetime | None, tz_name: str) -> date | None:
    """The calendar-date equivalent of the `localtime` filter, for code
    that needs to group/compare by date (the cluster date-range label,
    the trend chart) rather than render a formatted string."""
    if dt is None:
        return None
    return _as_aware_utc(dt).astimezone(ZoneInfo(tz_name)).date()
