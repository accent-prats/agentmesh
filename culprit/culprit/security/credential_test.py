"""Real connection tests for the settings screen's "Test connection"
button - not stubs. Each function actually calls the provider and reports
what happened; neither ever mutates anything (an auth-token fetch and a
Resource Graph read for Azure, one of two read-only Datadog endpoints
depending on credential shape - see test_datadog_credentials).

AI provider credential testing lives in
`shared/src/llm/credential_test.py` instead - it's a platform-level,
admin-managed concern owned by the Portal, not Culprit; see
`portal/api/routers/ai_providers.py`.
"""
from __future__ import annotations

from culprit.models.settings import AzureSettingsInput, DatadogSettingsInput, EmailOAuthSettingsInput, SmtpSettingsInput


def test_azure_credentials(cfg: AzureSettingsInput) -> tuple[bool, str]:
    """Returns (ok, message). Builds the credential the exact same way the
    real pipeline does (`collectors/azure_auth.py::build_credential`) -
    a service-principal credential if a tenant/client id and secret were
    given, otherwise DefaultAzureCredential (a managed identity, if this
    process happens to be running as one) - so a pass here means the real
    run will authenticate the same way, not just a similar one."""
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F401 - import-availability check only
    except ImportError:
        return False, "azure-identity is not installed in this deployment"

    from culprit.collectors.azure_auth import build_credential

    via = "a service principal" if cfg.tenant_id and cfg.client_id and cfg.client_secret else "this host's managed identity"

    try:
        credential = build_credential(cfg)

        token = credential.get_token("https://management.azure.com/.default")
        if not token or not token.token:
            return False, f"Authenticated via {via} but no access token was returned"

        if not cfg.subscription_ids:
            return True, f"Authenticated via {via} (no subscription id given, so Resource Graph access wasn't verified)"

        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        client = ResourceGraphClient(credential)
        client.resources(QueryRequest(subscriptions=cfg.subscription_ids, query="Resources | limit 1"))
        return True, f"Authenticated via {via} and queried Resource Graph across {len(cfg.subscription_ids)} subscription(s)"
    except Exception as exc:  # noqa: BLE001 - reporting the real error is the point of a test-connection button
        return False, f"Tried {via}: {str(exc)[:480]}"


def test_datadog_credentials(cfg: DatadogSettingsInput) -> tuple[bool, str]:
    """Builds the client the exact same way the real pipeline does
    (`collectors/datadog_auth.py::configure_datadog_client`), whether
    that's a Personal Access Token or the classic API key/App key pair,
    so a pass here means the real run will authenticate the same way.

    Two different validation calls, not one, because `/api/v1/validate`
    (AuthenticationApi.validate(), used for an API key) predates
    Application keys and PATs entirely and only ever checks DD-API-KEY -
    confirmed via Datadog's own docs and curl example, which sends no
    app-key header at all. A PAT lives in this app's DD-APPLICATION-KEY
    slot (see datadog_auth.py), so /validate structurally cannot
    authenticate one - it returns a clean 403 regardless of whether the
    PAT itself is good (found 2026-10-13: a real, valid PAT failed "Test
    connection" this way). `GET /api/v2/current_user` is Datadog's
    documented PAT-compatible equivalent: no scope requirement beyond
    being authenticated at all, same spirit as /validate for an API key."""
    try:
        from datadog_api_client import ApiClient
        from datadog_api_client.v1.api.authentication_api import AuthenticationApi
        from datadog_api_client.v2.api.users_api import UsersApi
    except ImportError:
        return False, "datadog-api-client is not installed in this deployment"

    if not cfg.api_key and not cfg.personal_access_token:
        return False, "No API key or Personal Access Token provided"

    from culprit.collectors.datadog_auth import configure_datadog_client

    via = "a Personal Access Token" if cfg.personal_access_token else "the API key"

    try:
        configuration = configure_datadog_client(cfg)

        with ApiClient(configuration) as api_client:
            if cfg.personal_access_token:
                response = UsersApi(api_client).get_current_user()
                email = getattr(getattr(response.data, "attributes", None), "email", "")
                return True, f"Authenticated via {via}" + (f" as {email}" if email else "")

            response = AuthenticationApi(api_client).validate()
            if response.valid:
                return True, f"Authenticated via {via}"
            return False, f"Datadog reported {via} as invalid"
    except Exception as exc:  # noqa: BLE001
        return False, f"Tried {via}: {str(exc)[:480]}"


def test_smtp_credentials(cfg: SmtpSettingsInput) -> tuple[bool, str]:
    """Opens the real connection and authenticates - the exact same
    sequence culprit/notifications/email_sender.py::send_email uses, up
    to but not including actually sending a message, so a pass here means
    the real send will connect and authenticate the same way."""
    import smtplib

    if not cfg.host:
        return False, "No SMTP host given"

    try:
        if cfg.encryption == "ssl":
            server = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=10)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=10)
        try:
            if cfg.encryption == "starttls":
                server.starttls()
            if cfg.username:
                server.login(cfg.username, cfg.password)
                return True, f"Connected to {cfg.host}:{cfg.port} and authenticated as {cfg.username}"
            return True, f"Connected to {cfg.host}:{cfg.port} (no credentials given, so login wasn't attempted)"
        finally:
            server.quit()
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:480]


def test_email_oauth_credentials(cfg: EmailOAuthSettingsInput) -> tuple[bool, str]:
    """Acquires a real OAuth token and completes the XOAUTH2 SMTP
    handshake against smtp.office365.com - up to but not including
    actually sending a message - so a pass here means the real send
    (notifications/email_sender.py::send_email_oauth) will authenticate
    the same way. Mirrors test_smtp_credentials' own "connect + "
    "authenticate only" contract, for the OAuth email method instead of
    the plain-password one."""
    import smtplib

    from culprit.notifications import m365_oauth

    if not (cfg.tenant_id and cfg.client_id and cfg.username):
        return False, "Tenant ID, Client ID, and mailbox username are all required"

    token, message = m365_oauth.acquire_token(cfg.tenant_id, cfg.client_id, cfg.username, cfg.password)
    if token is None:
        return False, message

    try:
        server = smtplib.SMTP(m365_oauth.SMTP_HOST, m365_oauth.SMTP_PORT, timeout=10)
        try:
            server.starttls()
            m365_oauth.xoauth2_login(server, cfg.username, token)
            return True, f"Authenticated as {cfg.username} via Microsoft 365 OAuth"
        finally:
            server.quit()
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:480]
