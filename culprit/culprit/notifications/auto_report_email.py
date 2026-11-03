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


def _build_subject_and_body(report: FleetReport, trigger_mode: TriggerMode, tz_name: str) -> tuple[str, str, str]:
    """Returns (subject, plain_text_body, html_body) - built once, used by
    whichever method is active (tcx-mailer's `body` is plain text; SMTP/
    OAuth's is HTML, same facts either way). Deliberately never includes a
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
        f"Culprit Patch RCA — {run.scope_name} — {date_str} — "
        f"{report.total_failed}/{report.total_machines} failed"
    )

    lines = [
        f"Run: {run.run_id} ({_TRIGGER_LABELS.get(trigger_mode, trigger_mode.value)})",
        f"Scope: {run.scope_name}",
        f"Window: {_format_local(run.started_at)} – {_format_local(run.ended_at)}",
        f"Machines scanned: {report.total_machines}",
        f"Failed: {report.total_failed} across {report.total_clusters} distinct cause(s)",
        f"Compliance: {report.compliance_pct}%",
    ]
    top = top_entries(report)
    if top:
        lines.append("")
        lines.append("Top causes:")
        for entry in top:
            badge = f" ({entry.recurrence_badge})" if entry.recurrence_badge else ""
            lines.append(
                f"  - {entry.cluster.size} machine(s) — {entry.result.title}{badge} "
                f"(confidence {entry.result.confidence:.0%})"
            )
    lines.append("")
    lines.append("The full Fleet Report (root cause + recommended fix per cause) and Installation")
    lines.append("Report are in the attached HTML file - open it directly, no extraction needed,")
    lines.append("nothing else to open, no network access required.")
    plain_text_body = "\n".join(lines)
    html_body = "<pre style=\"font-family:inherit\">" + "\n".join(
        line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for line in lines
    ) + "</pre>"
    return subject, plain_text_body, html_body


def send_report_on_completion(session_factory, report: FleetReport, trigger_mode: TriggerMode) -> None:
    """Best-effort - never raises. Resolves whichever email method is
    active, skips quietly (not an error) if it has no recipients
    configured, otherwise builds the offline bundle and sends it."""
    from culprit.db import repository
    from culprit.models.email import EmailStatus
    from culprit.notifications.email_sender import resolve_active_email_config
    from culprit.reporting.report_bundle import build_offline_report_bundle

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
            subject, plain_text_body, html_body = _build_subject_and_body(report, trigger_mode, tz_name)
            report_html_bytes = build_offline_report_bundle(session, report)
            attachments = [(f"culprit-report-{run_id}.html", report_html_bytes)]

            body = plain_text_body if method == "tcx_mailer" else html_body
            ok, message = send(cfg, recipients, subject, body, attachments)

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
