"""Real connection tests for the settings screen's "Test connection"
button - not stubs. Each function actually calls the provider and reports
what happened; neither ever mutates anything (an auth-token fetch and a
Resource Graph read for Azure, the Datadog SDK's own key-validation
endpoint for Datadog).

AI provider credential testing lives in
`shared/src/llm/credential_test.py` instead - it's a platform-level,
admin-managed concern owned by the Portal, not Culprit; see
`portal/api/routers/ai_providers.py`.
"""
from __future__ import annotations

from culprit.models.settings import AzureSettingsInput, DatadogSettingsInput


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
    """Uses Datadog's own AuthenticationApi.validate() - the documented,
    lightweight way to check a credential without any side effects.
    Builds the client the exact same way the real pipeline does
    (`collectors/datadog_auth.py::configure_datadog_client`), whether
    that's a Personal Access Token or the classic API key/App key pair,
    so a pass here means the real run will authenticate the same way.

    Note this specific call is a v1 API endpoint - Datadog's own PAT docs
    only confirm PAT compatibility for v2 calls, so a pass here is good
    evidence but not a guarantee that a PAT will also work for the v1
    Metrics/Monitors collection the real pipeline also does (see
    datadog_auth.py's docstring)."""
    try:
        from datadog_api_client import ApiClient
        from datadog_api_client.v1.api.authentication_api import AuthenticationApi
    except ImportError:
        return False, "datadog-api-client is not installed in this deployment"

    if not cfg.api_key and not cfg.personal_access_token:
        return False, "No API key or Personal Access Token provided"

    from culprit.collectors.datadog_auth import configure_datadog_client

    via = "a Personal Access Token" if cfg.personal_access_token else "the API key"

    try:
        configuration = configure_datadog_client(cfg)

        with ApiClient(configuration) as api_client:
            response = AuthenticationApi(api_client).validate()

        if response.valid:
            return True, f"Authenticated via {via}"
        return False, f"Datadog reported {via} as invalid"
    except Exception as exc:  # noqa: BLE001
        return False, f"Tried {via}: {str(exc)[:480]}"
