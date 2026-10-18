"""parse_leading_timestamp's new WindowsUpdate.log format, and
within_window() - the shared helpers added 2026-10-18 so guest-log parsers
in guest_windows.py/guest_linux.py can filter anomaly lines to the actual
collection window, instead of blindly scanning whatever a fixed
`-Tail 200`/`tail -n 200` happened to return. Found from a real user-shared
RCA: a VM's genuine Oct-16 failure produced zero guest-side evidence in a
scan run Oct-18, despite the guest Run Command completing successfully -
two days of subsequent log volume on a busy VM can push the relevant lines
out of a fixed-size tail, and conversely an unrelated old line still
sitting in the tail could get wrongly flagged as relevant to a different,
more recent investigation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from culprit.collectors.patch_extension_status import parse_leading_timestamp, within_window


def test_parse_leading_timestamp_handles_windowsupdate_log_format():
    """WindowsUpdate.log's ETW-decoded format uses a colon before the
    fractional seconds ("...:456"), not the comma core.log's Python
    logging uses ("...,456") - these look almost identical but need their
    own format entry."""
    ts = parse_leading_timestamp("2026-10-16 03:04:00:456  456  1a2b WU  WARNING: ...")
    assert ts == datetime(2026, 10, 16, 3, 4, 0, 456000, tzinfo=timezone.utc)


def test_parse_leading_timestamp_still_handles_cbs_log_format():
    """CBS.log's leading timestamp ("2026-10-16 03:04:00, Info ...") was
    already covered by the existing plain-ISO 19-char format - this pins
    that it still works after adding the new WindowsUpdate.log entry."""
    ts = parse_leading_timestamp("2026-10-16 03:04:00, Error CBS Failed to CSI Transaction")
    assert ts == datetime(2026, 10, 16, 3, 4, 0, tzinfo=timezone.utc)


def test_within_window_keeps_a_timestamp_inside_the_window():
    window_start = datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc)
    window_end = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc)
    ts = datetime(2026, 10, 16, 3, 0, tzinfo=timezone.utc)
    assert within_window(ts, window_start, window_end) is True


def test_within_window_drops_a_timestamp_before_the_window():
    window_start = datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc)
    window_end = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc)
    ts = datetime(2026, 10, 14, 0, 0, tzinfo=timezone.utc)  # 2 days before window_start
    assert within_window(ts, window_start, window_end) is False


def test_within_window_drops_a_timestamp_well_after_the_window():
    window_start = datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc)
    window_end = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc)
    ts = datetime(2026, 10, 18, 0, 0, tzinfo=timezone.utc)  # 2 days after window_end
    assert within_window(ts, window_start, window_end) is False


def test_within_window_keeps_a_timestamp_just_after_window_end_within_the_buffer():
    """Collection genuinely happens slightly after window_end was computed
    (clock skew, the time the Run Command itself takes) - a small buffer
    past window_end must still count as in-window."""
    window_start = datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc)
    window_end = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc)
    ts = window_end + timedelta(minutes=30)
    assert within_window(ts, window_start, window_end) is True


def test_within_window_treats_an_unparseable_timestamp_as_in_window():
    """A line whose own timestamp couldn't be extracted (ts=None) must
    stay in-window - fail OPEN, since excluding it risks silently dropping
    a real anomaly just because its format wasn't recognized."""
    window_start = datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc)
    window_end = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc)
    assert within_window(None, window_start, window_end) is True


def test_within_window_is_a_no_op_when_no_window_is_given():
    """Callers that don't care about windowing (existing tests, demo code)
    get unfiltered behavior - window_start/window_end default to None."""
    far_past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert within_window(far_past, None, None) is True
