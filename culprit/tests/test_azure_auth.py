"""Unit coverage for azure_auth.py::build_credential - the single place
every real Azure collector (Resource Graph, Activity Log, Log Analytics,
both guest-OS Run Command collectors, via api/deps.py::build_live_collectors)
and the settings screen's "Test connection" button (credential_test.py::
test_azure_credentials) get their Azure credential from.

Never exercised anywhere else in the suite before this file: test_live_run.py
bypasses it entirely by mocking build_live_collectors wholesale (its own
docstring says "everything Azure-shaped is mocked"), and test_settings_api.py
mocks test_azure_credentials itself rather than letting it call build_credential
for real. Added 2026-10-10 alongside the settings screen's managed-identity
toggle, specifically to prove the blank-fields branch actually selects
DefaultAzureCredential rather than just being documented to."""
from __future__ import annotations

import pytest

pytest.importorskip("azure.identity")  # optional `culprit[azure]` extra - see pyproject.toml

from culprit.collectors.azure_auth import build_credential
from culprit.models.settings import AzureSettingsInput


def test_no_config_at_all_uses_default_azure_credential(monkeypatch):
    sentinel = object()
    monkeypatch.setattr("azure.identity.DefaultAzureCredential", lambda: sentinel)

    assert build_credential(None) is sentinel


def test_blank_tenant_client_secret_uses_default_azure_credential(monkeypatch):
    """The managed-identity path: subscription ids given, auth fields all
    blank - the exact shape the settings screen's "Managed identity" radio
    now saves (see settings.html.j2::azureAuthFields)."""
    sentinel = object()
    monkeypatch.setattr("azure.identity.DefaultAzureCredential", lambda: sentinel)

    cfg = AzureSettingsInput(subscription_ids=["sub-1"], tenant_id="", client_id="", client_secret="")
    assert build_credential(cfg) is sentinel


@pytest.mark.parametrize("missing_field", ["tenant_id", "client_id", "client_secret"])
def test_a_partially_filled_service_principal_still_falls_back(monkeypatch, missing_field):
    """All three fields are required for a service principal - two out of
    three must not silently construct a credential with an empty secret."""
    sentinel = object()
    monkeypatch.setattr("azure.identity.DefaultAzureCredential", lambda: sentinel)

    fields = {"tenant_id": "t", "client_id": "c", "client_secret": "s"}
    fields[missing_field] = ""
    assert build_credential(AzureSettingsInput(**fields)) is sentinel


def test_full_service_principal_uses_client_secret_credential(monkeypatch):
    captured = {}

    class FakeClientSecretCredential:
        def __init__(self, tenant_id, client_id, client_secret):
            captured["args"] = (tenant_id, client_id, client_secret)

    monkeypatch.setattr("azure.identity.ClientSecretCredential", FakeClientSecretCredential)

    cfg = AzureSettingsInput(tenant_id="t", client_id="c", client_secret="s")
    credential = build_credential(cfg)

    assert isinstance(credential, FakeClientSecretCredential)
    assert captured["args"] == ("t", "c", "s")
