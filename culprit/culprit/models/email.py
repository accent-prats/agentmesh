"""Email-a-run's-report models - the request/response/audit shapes for
api/routes_notifications.py. See culprit/notifications/ for the actual
SMTP send, and culprit/models/settings.py::SmtpSettingsInput/View for the
mail-server configuration this reads.
"""
from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from culprit.models.settings import EMAIL_ADDRESS_RE


class EmailStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"


class SendReportRequest(BaseModel):
    # Empty means "use the stored default DL" (SmtpSettingsView.
    # default_recipients) - routes_notifications.py is what resolves that,
    # this model only carries what the caller actually supplied.
    recipients: list[str] = Field(default_factory=list)
    # Required, caller-supplied - same reasoning and the same blank-reject
    # discipline as RemediationActionRequest.requested_by: every outbound
    # email needs an identifiable human attached, not just a truthy string.
    requested_by: str = Field(..., min_length=1)
    # Optional free text shown above the digest in the email body - e.g.
    # "FYI, see the repeat offender in cluster 3" - never required.
    note: str = ""

    @field_validator("requested_by")
    @classmethod
    def _requested_by_must_not_be_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("requested_by must not be blank")
        return stripped

    @field_validator("recipients")
    @classmethod
    def _recipients_must_look_like_emails(cls, v: list[str]) -> list[str]:
        # Found in review 2026-10-14: this per-send override field had no
        # validation at all - unlike SmtpSettingsInput.default_recipients,
        # a caller could hand send_email() an arbitrary string, including
        # one containing \r/\n, which email.message.EmailMessage then
        # raised a bare ValueError on (a 500, with no audit log row - see
        # notifications/email_sender.py). Same pattern, same regex, as
        # the stored default DL - a 422 here now, before this ever reaches
        # the send path.
        import re

        for addr in v:
            if not re.match(EMAIL_ADDRESS_RE, addr):
                raise ValueError(f"'{addr}' doesn't look like an email address")
        return v


class SendReportResponse(BaseModel):
    ok: bool
    recipients: list[str]
    message: str


class EmailLogEntry(BaseModel):
    """One row of GET /settings/smtp/log - every report email ever sent,
    most recent first."""

    id: int
    run_id: str
    recipients: list[str]
    requested_by: str
    sent_at: datetime
    status: EmailStatus
    message: str
