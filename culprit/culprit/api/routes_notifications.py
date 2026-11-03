"""Email a specific run's report to a recipient list - the one feature in
this app that sends outbound mail. See culprit/notifications/ for the
actual SMTP mechanics and culprit/models/settings.py::SmtpSettingsInput
for the mail-server configuration this reads.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from culprit.api import deps
from culprit.models.email import EmailStatus, SendReportRequest, SendReportResponse

router = APIRouter(tags=["notifications"])


@router.post("/runs/{run_id}/email", response_model=SendReportResponse)
def send_report_email(run_id: str, body: SendReportRequest) -> SendReportResponse:
    from culprit.db import repository
    from culprit.notifications.email_sender import (
        build_report_digest,
        is_email_method_configured,
        resolve_active_email_config,
    )
    from culprit.reporting.report_bundle import build_offline_report_bundle

    with deps.get_session_factory()() as session:
        report = repository.load_fleet_report(session, run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

        # Which configured method (SMTP, Microsoft 365 OAuth, or IT's own
        # tcx-mailer utility) actually sends - a deliberate, explicit admin
        # choice (models/settings.py::EmailMethodSettingsInput), never
        # "whichever one happens to be filled in".
        method, cfg, send = resolve_active_email_config(session)
        if not is_email_method_configured(method, cfg):
            # Keeps each method's own pre-existing reason string exactly
            # (fleet_report.html.j2::describeEmailError matches these
            # literally - "smtp_not_configured" has no "email_" prefix,
            # an inconsistency already baked into the UI before this change,
            # not introduced by it) and adds a new one for the new method.
            reason = {
                "smtp": "smtp_not_configured",
                "oauth": "email_oauth_not_configured",
                "tcx_mailer": "email_tcx_mailer_not_configured",
            }[method]
            raise HTTPException(status_code=409, detail={"reason": reason})

        recipients = body.recipients or cfg.default_recipients
        if not recipients:
            raise HTTPException(status_code=400, detail="No recipients given and no default recipient list is configured")

        tz_name = repository.load_display_timezone_settings(session).timezone
        subject, html_body = build_report_digest(report, body.note, body.requested_by, tz_name=tz_name)
        # Found by review 2026-11-02, against a real production send: this
        # digest used to link out to a live "Open full report" page instead
        # of attaching anything - exactly the "depends on reaching a live
        # server" shape the user explicitly ruled out for every Culprit
        # email, not just the auto-send one. Now attaches the same fully
        # self-contained offline bundle auto-send uses, so both paths carry
        # the same guarantee.
        report_bundle_bytes = build_offline_report_bundle(session, report)
        attachments = [(f"culprit-report-{run_id}.zip", report_bundle_bytes)]
        ok, message = send(cfg, recipients, subject, html_body, attachments)

        repository.save_email_log(
            session, run_id=run_id, recipients=recipients, requested_by=body.requested_by,
            sent_at=datetime.now(timezone.utc), status=EmailStatus.SUCCESS if ok else EmailStatus.FAILED,
            message=message,
        )

    return SendReportResponse(ok=ok, recipients=recipients, message=message)
