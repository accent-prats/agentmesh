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
    from culprit.notifications.email_sender import build_report_digest, send_email
    from culprit.reporting.notify import report_url_from_request

    with deps.get_session_factory()() as session:
        report = repository.load_fleet_report(session, run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

        smtp_cfg = repository.load_smtp_settings(session)
        if not smtp_cfg.host:
            raise HTTPException(status_code=409, detail={"reason": "smtp_not_configured"})

        recipients = body.recipients or smtp_cfg.default_recipients
        if not recipients:
            raise HTTPException(status_code=400, detail="No recipients given and no default recipient list is configured")

        report_url = report_url_from_request(request, run_id)
        subject, html_body = build_report_digest(report, report_url, body.note, body.requested_by)
        ok, message = send_email(smtp_cfg, recipients, subject, html_body)

        repository.save_email_log(
            session, run_id=run_id, recipients=recipients, requested_by=body.requested_by,
            sent_at=datetime.now(timezone.utc), status=EmailStatus.SUCCESS if ok else EmailStatus.FAILED,
            message=message,
        )

    return SendReportResponse(ok=ok, recipients=recipients, message=message)
