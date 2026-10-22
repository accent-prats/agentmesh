"""Email a specific run's report to a recipient list - the one feature in
this app that sends outbound mail. See culprit/notifications/ for the
actual SMTP mechanics and culprit/models/settings.py::SmtpSettingsInput
for the mail-server configuration this reads.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from culprit.api import deps
from culprit.models.email import EmailStatus, SendReportRequest, SendReportResponse

router = APIRouter(tags=["notifications"])


@router.post("/runs/{run_id}/email", response_model=SendReportResponse)
def send_report_email(run_id: str, request: Request, body: SendReportRequest) -> SendReportResponse:
    from culprit.db import repository
    from culprit.notifications.email_sender import build_report_digest, send_email, send_email_oauth
    from culprit.reporting.notify import report_url_from_request

    with deps.get_session_factory()() as session:
        report = repository.load_fleet_report(session, run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

        # Which configured method (SMTP, or Microsoft 365 OAuth) actually
        # sends - a deliberate, explicit admin choice (models/settings.py::
        # EmailMethodSettingsInput), never "whichever one happens to be
        # filled in". "smtp" is the default so this branch never changes
        # behavior for a deployment that hasn't touched the new OAuth tab.
        method = repository.load_email_method(session)
        if method == "oauth":
            cfg = repository.load_email_oauth_settings(session)
            if not (cfg.tenant_id and cfg.client_id and cfg.username):
                raise HTTPException(status_code=409, detail={"reason": "email_oauth_not_configured"})
            send = send_email_oauth
        else:
            cfg = repository.load_smtp_settings(session)
            if not cfg.host:
                raise HTTPException(status_code=409, detail={"reason": "smtp_not_configured"})
            send = send_email

        recipients = body.recipients or cfg.default_recipients
        if not recipients:
            raise HTTPException(status_code=400, detail="No recipients given and no default recipient list is configured")

        report_url = report_url_from_request(request, run_id)
        tz_name = repository.load_display_timezone_settings(session).timezone
        subject, html_body = build_report_digest(report, report_url, body.note, body.requested_by, tz_name=tz_name)
        ok, message = send(cfg, recipients, subject, html_body)

        repository.save_email_log(
            session, run_id=run_id, recipients=recipients, requested_by=body.requested_by,
            sent_at=datetime.now(timezone.utc), status=EmailStatus.SUCCESS if ok else EmailStatus.FAILED,
            message=message,
        )

    return SendReportResponse(ok=ok, recipients=recipients, message=message)
