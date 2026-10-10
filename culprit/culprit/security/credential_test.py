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
    lightweight way to check an API key without any side effects."""
    try:
        from datadog_api_client import ApiClient, Configuration
        from datadog_api_client.v1.api.authentication_api import AuthenticationApi
    except ImportError:
        return False, "datadog-api-client is not installed in this deployment"

    if not cfg.api_key:
        return False, "No API key provided"

    try:
        configuration = Configuration()
        configuration.api_key["apiKeyAuth"] = cfg.api_key
        if cfg.app_key:
            configuration.api_key["appKeyAuth"] = cfg.app_key
        configuration.server_variables["site"] = cfg.site or "datadoghq.com"

        with ApiClient(configuration) as api_client:
            response = AuthenticationApi(api_client).validate()

        if response.valid:
            return True, "API key validated"
        return False, "Datadog reported this API key as invalid"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:500]
