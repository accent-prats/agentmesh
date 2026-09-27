from __future__ import annotations

from datetime import datetime, timezone

from culprit.models.evidence import Source, TimelineEvent
from culprit.security.scrub import scrub_event, scrub_text


def test_scrub_redacts_aws_key():
    text = "found credential AKIAABCDEFGHIJKLMNOP in config"
    assert "AKIAABCDEFGHIJKLMNOP" not in scrub_text(text)
    assert "REDACTED:aws_access_key" in scrub_text(text)


def test_scrub_redacts_bearer_token():
    text = "Authorization: Bearer abcDEF123456789012345.xyz"
    out = scrub_text(text)
    assert "abcDEF123456789012345" not in out


def test_scrub_redacts_basic_auth_in_url():
    text = "connecting to https://user:hunter2@example.com/api"
    out = scrub_text(text)
    assert "hunter2" not in out


def test_scrub_redacts_generic_password_kv():
    text = "password=SuperSecret123 was rejected"
    out = scrub_text(text)
    assert "SuperSecret123" not in out


def test_scrub_leaves_ip_and_email_by_default():
    text = "connection from 10.0.0.5 by alice@example.com"
    out = scrub_text(text, redact_network_and_pii=False)
    assert "10.0.0.5" in out
    assert "alice@example.com" in out


def test_scrub_strict_mode_redacts_ip_and_email():
    text = "connection from 10.0.0.5 by alice@example.com"
    out = scrub_text(text, redact_network_and_pii=True)
    assert "10.0.0.5" not in out
    assert "alice@example.com" not in out


def test_scrub_event_scrubs_summary_and_string_details():
    ev = TimelineEvent(
        ts=datetime.now(timezone.utc),
        source=Source.GUEST_LINUX,
        kind="k",
        summary="password=hunter2",
        detail={"raw_line": "password=hunter2", "flag": True},
        raw_ref="ref",
    )
    scrubbed = scrub_event(ev)
    assert "hunter2" not in scrubbed.summary
    assert "hunter2" not in scrubbed.detail["raw_line"]
    assert scrubbed.detail["flag"] is True  # non-string values pass through untouched
