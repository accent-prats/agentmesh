"""Microsoft 365 / Exchange Online email delivery via OAuth2 instead of a
long-lived SMTP app password.

The Resource Owner Password Credentials (ROPC) flow exchanges a mailbox's
own Azure AD username/password for an access token, which then
authenticates the SAME smtp.office365.com SMTP session every other
Microsoft 365 mail sender uses - via the XOAUTH2 SASL mechanism in place
of a plain AUTH LOGIN/PASSWORD. This is the mechanism behind the Settings
screen's "Microsoft 365 (OAuth)" email delivery method
(models/settings.py::EmailOAuthSettingsInput) - a SIBLING to the existing
SMTP path (email_sender.py::send_email), never a replacement for it; see
api/routes_notifications.py for how the two are selected between.

Requires the optional `msal` dependency (pip install 'culprit[oauth]') -
guarded the same way azure-mgmt-compute is guarded in
collectors/guest_linux.py, so a deployment that never configures this
method doesn't need the package installed at all.

ROPC itself needs a real Azure AD App Registration (the `client_id`) with
"Allow public client flows" enabled and the SMTP.Send delegated
permission, admin-consented - this is a one-time setup the tenant's own
Azure AD admin does, not something Culprit can create for itself (the
same reason Azure's own tenant_id/client_id fields on the Azure settings
tab aren't inferred either). Microsoft's own documentation also flags
ROPC as a legacy flow some tenants' Conditional Access policies block
outright, since it can't satisfy an MFA challenge the way a browser-based
sign-in can - a clean credential rejection here, with the account's
username/password otherwise correct, usually means that, not a typo in
the settings form."""
from __future__ import annotations

import base64
import smtplib

try:
    import msal

    _MSAL_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via the "not installed" branch below
    _MSAL_AVAILABLE = False

# Fixed for every Microsoft 365 / Exchange Online tenant - unlike
# SmtpSettingsInput's host/port/encryption, there is nothing tenant-
# specific to configure here.
SMTP_HOST = "smtp.office365.com"
SMTP_PORT = 587

# Exchange Online's own documented scope for protocol auth (IMAP/POP/SMTP)
# under OAuth - distinct from Microsoft Graph's "Mail.Send", which is for
# the separate Graph sendMail REST API this module deliberately does NOT
# use (XOAUTH2-over-SMTP instead, so the rest of the send path - message
# construction, recipients, HTML body - can stay the same EmailMessage/
# smtplib shape email_sender.py already uses for the plain-password case).
_SCOPES = ["https://outlook.office365.com/SMTP.Send"]


def acquire_token(tenant_id: str, client_id: str, username: str, password: str) -> tuple[str | None, str]:
    """Returns (access_token, message). access_token is None on failure,
    with `message` describing why - never raises, the same (ok-ish,
    message) contract as every other credential path in this codebase
    (security/credential_test.py, notifications/email_sender.py::
    send_email). Never logs or returns the mailbox password - MSAL's own
    error payload describes the failure (bad credentials, admin consent
    required, Conditional Access blocking ROPC) without embedding it."""
    if not _MSAL_AVAILABLE:
        return None, "msal is not installed on this deployment - install the 'oauth' extra (pip install 'culprit[oauth]')"
    if not (tenant_id and client_id and username and password):
        return None, "Tenant ID, Client ID, username, and password are all required"

    try:
        app = msal.PublicClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant_id}")
        result = app.acquire_token_by_username_password(username, password, scopes=_SCOPES)
    except Exception as exc:  # noqa: BLE001 - any MSAL/network failure degrades to (None, message), never raises
        return None, f"{type(exc).__name__}: {str(exc)[:400]}"

    if result and "access_token" in result:
        return result["access_token"], "ok"
    desc = (result or {}).get("error_description") or (result or {}).get("error") or "Unknown authentication error"
    return None, str(desc)[:480]


def xoauth2_login(server: smtplib.SMTP, username: str, access_token: str) -> None:
    """Authenticates an already-connected (and, if using STARTTLS, already
    upgraded) SMTP session using the XOAUTH2 SASL mechanism - the OAuth
    equivalent of smtplib.SMTP.login(), which only knows plain AUTH LOGIN/
    PLAIN. Raises smtplib.SMTPAuthenticationError on a non-235 response,
    same as .login() does, so every existing caller's try/except around
    the plain-auth SMTP path already handles this failure mode unchanged."""
    auth_string = f"user={username}\x01auth=Bearer {access_token}\x01\x01"
    b64 = base64.b64encode(auth_string.encode()).decode()
    code, resp = server.docmd("AUTH", "XOAUTH2 " + b64)
    if code != 235:
        raise smtplib.SMTPAuthenticationError(code, resp)
