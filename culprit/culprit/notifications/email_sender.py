"""Builds and sends a specific run's report email - the mechanics behind
api/routes_notifications.py::POST /runs/{run_id}/email.
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage

from culprit.models.report import FleetReport
from culprit.models.settings import SmtpSettingsInput

_SMTP_TIMEOUT_SECONDS = 10.0


def build_report_digest(report: FleetReport, report_url: str | None, note: str, requested_by: str) -> tuple[str, str]:
    """Returns (subject, html_body). Same "top findings + headline facts"
    shape as reporting/notify.py's Teams/Slack digest - imports its
    top_entries rather than re-selecting independently, so this email's
    findings list always matches what the webhook digest already shows."""
    from culprit.reporting.notify import top_entries as select_top_entries
    from culprit.reporting.render import render_email_report_html

    subject = f"Culprit · {report.run.scope_name} — {report.total_failed}/{report.total_machines} failed"
    html_body = render_email_report_html(
        report, top_entries=select_top_entries(report), report_url=report_url, note=note, requested_by=requested_by,
    )
    return subject, html_body


def send_email(cfg: SmtpSettingsInput, to: list[str], subject: str, html_body: str) -> tuple[bool, str]:
    """Real smtplib send - never raises, mirrors
    security/credential_test.py's (ok, message) shape and its same
    truncate-the-exception-to-480-chars convention. `cfg` is a fully
    decrypted SmtpSettingsInput (db/repository.py::load_smtp_settings) -
    callers never pass a Fernet ciphertext here."""
    if not cfg.host:
        return False, "SMTP is not configured for this deployment"
    if not to:
        return False, "No recipients given"

    # Message construction moved inside the try (found in review
    # 2026-10-14): SendReportRequest.recipients is now validated against
    # EMAIL_ADDRESS_RE before this function is ever called, which already
    # rejects the \r/\n that made email.message raise a bare, uncaught
    # ValueError here - but that validation lives in a caller, not in this
    # function, and this is the one place that actually touches
    # EmailMessage's header-setting. A future second caller skipping that
    # validation should degrade to a logged (False, message), the same
    # contract this function already promises for every other failure, not
    # bypass it with an unhandled 500.
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = f"{cfg.from_name} <{cfg.from_address}>" if cfg.from_address else cfg.from_name
        msg["To"] = ", ".join(to)
        msg.set_content("This report requires an HTML-capable email client to view.")
        msg.add_alternative(html_body, subtype="html")

        if cfg.encryption == "ssl":
            server = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=_SMTP_TIMEOUT_SECONDS)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=_SMTP_TIMEOUT_SECONDS)
        try:
            if cfg.encryption == "starttls":
                server.starttls()
            if cfg.username:
                server.login(cfg.username, cfg.password)
            server.send_message(msg)
        finally:
            server.quit()
        return True, f"Sent to {len(to)} recipient(s)"
    except Exception as exc:  # noqa: BLE001 - reporting the real error is the point of a send attempt
        return False, str(exc)[:480]
