"""Automatically emails a run's report the instant it finishes - scheduled
or ad hoc, never the demo run (see pipeline/live_run.py::execute_live_run,
the one shared call path both real triggers go through and the only place
this is hooked in). This is a NEW capability, not a replacement for the
existing manual "Send Report" button on the Fleet Report page
(api/routes_notifications.py) - that button's own digest-style email is
untouched; this module builds its own richer, run-summary email with the
full offline report bundle (reporting/report_bundle.py) attached.

Best-effort throughout, like every other post-run side effect in this
codebase (Teams/Slack notify, the Installation Report build) - a failure
here must never fail a run that already completed successfully.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from culprit.models.patch_run import TriggerMode
from culprit.models.report import FleetReport

log = logging.getLogger(__name__)


def _build_subject_and_body(report: FleetReport, tz_name: str) -> tuple[str, str]:
    """Returns (subject, html_body) - one body, sent to every method the
    same way (see `send_report_on_completion` below).

    **History, in order, all against real sent emails**: this function
    originally built a plain-text body special-cased for tcx-mailer, on
    the never-verified assumption that tcx-mailer needed plain text while
    SMTP/OAuth got HTML. A real send showed it collapsed into one
    unformatted run-on block in Outlook. A first fix (switching that
    plain-text body's line joiner from "\\n" to "\\r\\n") made no visible
    difference - the real signature (dividers/labels joined by exactly one
    space each, even across blank-line breaks) was an HTML renderer
    collapsing whitespace, not a dropped-newline transport issue.
    tcx-mailer's own `send_email(body=...)` has no content-type parameter
    at all, so whatever the real vendor/Siemens relay does with that
    string is a fixed, uninspectable choice - the only lever this app
    controls is the string's own shape. A second fix (2026-11-16) switched
    every method onto the same hand-built `<pre>`-wrapped HTML block
    already used elsewhere, which worked (confirmed via a real send) but
    looked plain next to the richer branded email the user remembered
    getting before this auto-send feature existed.

    **Current fix (2026-11-17, a styling enhancement, not a bug)**: reuses
    `reporting/render.py::render_email_report_html` - the same branded,
    stat-tile template `api/routes_notifications.py::send_report_email`
    (the manual "Send Report" button) already sends, real HTML markup
    (tables/divs, not a bare `<pre>` block) that happens to also satisfy
    everything the whitespace-collapse investigation above established.
    `trigger_mode` (Scheduled/Ad hoc/etc) is deliberately not shown here -
    this template never showed it even before this auto-send feature
    existed, and the user's own reference screenshot of "the version we
    used to get" didn't have it either. Deliberately never includes a
    "view live" link of any kind - found 2026-11-02, against a real send:
    the user's "no broken links" requirement means NO link to a live
    server at all - every fact here comes from `report` and the attached
    offline bundle, nothing that depends on this deployment's own
    reachability (`render_email_report_html` itself has no `report_url`
    parameter for the same reason)."""
    from culprit.reporting.notify import top_entries
    from culprit.reporting.render import render_email_report_html

    zone = ZoneInfo(tz_name)
    run = report.run
    when = (run.ended_at or run.started_at or datetime.now(timezone.utc))
    when_local = (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).astimezone(zone)
    date_str = when_local.strftime("%Y-%m-%d")

    subject = (
        f"PatchInsight Patch RCA — {run.scope_name} — {date_str} — "
        f"{report.total_failed}/{report.total_machines} failed"
    )

    html_body = render_email_report_html(
        report, top_entries=top_entries(report), note="",
        requested_by="system (auto-send on completion)", tz_name=tz_name,
    )
    return subject, html_body


def send_report_on_completion(session_factory, report: FleetReport, trigger_mode: TriggerMode) -> None:
    """Best-effort - never raises. Resolves whichever email method is
    active, skips quietly (not an error) if it has no recipients
    configured, otherwise builds the offline bundle and sends it."""
    from culprit.db import repository
    from culprit.models.email import EmailStatus
    from culprit.notifications.email_sender import resolve_active_email_config
    from culprit.reporting.report_bundle import build_offline_report_bundle, offline_report_attachment_filename

    run_id = report.run.run_id
    try:
        with session_factory() as session:
            method, cfg, send = resolve_active_email_config(session)
            recipients = cfg.default_recipients
            if not recipients:
                log.info(
                    "auto_report_email: no default recipients configured for the active method (%s) - "
                    "skipping auto-send for run %s", method, run_id,
                )
                return

            tz_name = repository.load_display_timezone_settings(session).timezone
            subject, html_body = _build_subject_and_body(report, tz_name)
            report_bundle_bytes = build_offline_report_bundle(session, report)
            attachments = [(offline_report_attachment_filename(report, tz_name), report_bundle_bytes)]

            ok, message = send(cfg, recipients, subject, html_body, attachments)

            repository.save_email_log(
                session, run_id=run_id, recipients=recipients, requested_by="system (auto-send on completion)",
                sent_at=datetime.now(timezone.utc), status=EmailStatus.SUCCESS if ok else EmailStatus.FAILED,
                message=message,
            )
            if ok:
                log.info("auto_report_email: sent report for run %s via %s to %d recipient(s)", run_id, method, len(recipients))
            else:
                log.warning("auto_report_email: failed to send report for run %s via %s: %s", run_id, method, message)
    except Exception:  # noqa: BLE001 - must not fail a run that already completed successfully
        log.exception("auto_report_email: failed to auto-send the report email for run %s", run_id)
