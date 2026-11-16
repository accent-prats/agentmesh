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

_TRIGGER_LABELS = {
    TriggerMode.SCHEDULED: "Scheduled",
    TriggerMode.AD_HOC: "Ad hoc",
    TriggerMode.EVENT_DRIVEN: "Event-driven",
    TriggerMode.PRE_FLIGHT: "Pre-flight",
}


def _build_subject_and_body(report: FleetReport, trigger_mode: TriggerMode, tz_name: str) -> tuple[str, str]:
    """Returns (subject, html_body) - one body, sent to every method the
    same way.

    **Two wrong theories, corrected 2026-11-16 against real sent emails**:
    this function originally built a SEPARATE plain-text body for
    tcx-mailer specifically, on the unverified assumption (never checked
    against the real vendor behavior) that "tcx-mailer's body is plain
    text, SMTP/OAuth's is HTML." A first real send showed the body
    collapsed into one unformatted run-on block in Outlook; the first fix
    attempt (switching that plain-text body's line joiner from a bare
    "\\n" to "\\r\\n", theorizing a CRLF-vs-bare-LF mail-relay mismatch) was
    deployed and tested against a second real send - it made no visible
    difference at all. The real culprit: the delivered message's dividers
    and labeled fields were joined by exactly ONE space each, including
    across what should have been blank-line section breaks - the
    signature of an HTML renderer collapsing every run of whitespace
    (newlines included) to a single space, not of a transport that merely
    drops `\\n` characters. tcx-mailer's own `send_email(body=...)` has no
    content-type parameter at all (confirmed by reading both this
    codebase's adapter and its vendor-matching test fixture) - whatever
    the real vendor/Siemens relay does with that string is a fixed,
    uninspectable choice on their end, not something this app can
    negotiate. The one lever this app DOES control is the shape of the
    string itself, and `api/routes_notifications.py::send_report_email`
    (the pre-existing, already-field-tested manual "Send Report" button)
    already sends the SAME html_body to every method, tcx-mailer included,
    with no special case - this function now matches that already-proven
    design instead of its own never-verified one. Deliberately never includes a
    "view live" link of any kind, even a conditional one - found 2026-11-02,
    against a real send: the user's "no broken links" requirement means NO
    link to a live server at all, full stop, not "a link when one happens
    to resolve" - every fact here comes from `report`/`trigger_mode` and the
    attached offline bundle, nothing that depends on this deployment's own
    reachability."""
    from culprit.reporting.notify import top_entries

    zone = ZoneInfo(tz_name)

    def _format_local(dt: datetime | None) -> str:
        # Same "%Y-%m-%d %H:%M" + tzname shape as reporting/timezone_display.py's
        # `localtime` Jinja filter every report page already uses - found by
        # review 2026-11-02: a bare str(datetime) here left real run windows
        # reading like "2026-11-02 12:13:48.373324" (raw UTC, microseconds and
        # all), nowhere near as clean as the subject line's own date_str.
        if dt is None:
            return "unknown"
        localized = (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(zone)
        return f"{localized.strftime('%Y-%m-%d %H:%M')} {localized.tzname()}"

    run = report.run
    when = (run.ended_at or run.started_at or datetime.now(timezone.utc))
    when_local = (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).astimezone(zone)
    date_str = when_local.strftime("%Y-%m-%d")

    subject = (
        f"PatchInsight Patch RCA — {run.scope_name} — {date_str} — "
        f"{report.total_failed}/{report.total_machines} failed"
    )

    divider = "-" * 46

    lines = [
        f"PATCHINSIGHT PATCH RCA — {run.scope_name}",
        divider,
        "",
        f"Run:               {run.run_id} ({_TRIGGER_LABELS.get(trigger_mode, trigger_mode.value)})",
        f"Window:            {_format_local(run.started_at)} – {_format_local(run.ended_at)}",
        f"Machines scanned:  {report.total_machines}",
        f"Failed:            {report.total_failed} across {report.total_clusters} distinct cause(s)",
        f"Compliance:        {report.compliance_pct}%",
    ]
    top = top_entries(report)
    if top:
        lines.append("")
        lines.append("TOP CAUSES")
        lines.append(divider)
        for entry in top:
            badge = f" ({entry.recurrence_badge})" if entry.recurrence_badge else ""
            lines.append(
                f"  * {entry.cluster.size} machine(s) — {entry.result.title}{badge}"
            )
            lines.append(f"    confidence {entry.result.confidence:.0%}")
            lines.append("")
        lines.pop()  # drop the trailing blank line after the last cause
    lines.append("")
    lines.append(divider)
    lines.append("The full Fleet Report (root cause + recommended fix per cause) and Installation")
    lines.append("Report are in the attached zip - extract it and open report.html. Nothing in it")
    lines.append("needs network access.")
    # A real HTML <pre> block, not a plain-text string - see this function's
    # own docstring for why a plain-text body (with either a bare "\n" or a
    # "\r\n" joiner - both tried and both disproven against real sent
    # emails) never survives whatever the tcx-mailer/Siemens relay does
    # with it. <pre> preserves whitespace/line breaks by the HTML spec
    # itself, independent of any stylesheet - the one thing every method
    # (SMTP/OAuth's genuine multipart HTML, and now tcx-mailer's opaque
    # body string) can rely on rendering the same way.
    html_body = "<pre style=\"font-family:inherit\">" + "\n".join(
        line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for line in lines
    ) + "</pre>"
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
            subject, html_body = _build_subject_and_body(report, trigger_mode, tz_name)
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
