"""Azure and Datadog connection settings - the API behind /culprit/settings.

Every value round-trips through culprit/db/repository.py, which is the
only layer that knows about encryption; nothing here ever handles
ciphertext directly, and nothing here ever echoes a secret back once
saved - GET responses report `configured: bool`, never the value.

The deep RCA agent's own AI provider is configured on the Portal's admin
AI Providers screen instead, not here - see
`portal/api/routers/ai_providers.py` and `api/deps.py::get_rca_agent`.
"""
from __future__ import annotations

from fastapi import APIRouter

from culprit.api import deps
from culprit.models.settings import (
    AzureSettingsInput,
    AzureSettingsView,
    DatadogSettingsInput,
    DatadogSettingsView,
)
from culprit.security.credential_test import test_azure_credentials, test_datadog_credentials

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/azure", response_model=AzureSettingsView)
def get_azure_settings() -> AzureSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.azure_settings_view(session)


@router.put("/azure", response_model=AzureSettingsView)
def put_azure_settings(body: AzureSettingsInput) -> AzureSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_azure_settings(session, body)
        return repository.azure_settings_view(session)


@router.post("/azure/test")
def test_azure(body: AzureSettingsInput | None = None) -> dict:
    """Tests the given values if provided (so you can verify before
    saving), otherwise re-tests whatever is already stored - either way
    the result is persisted so the settings screen shows when this was
    last checked and whether it passed."""
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        cfg = body if body and (body.subscription_ids or body.tenant_id) else repository.load_azure_settings(session)
        ok, message = test_azure_credentials(cfg)
        repository.record_settings_test_result(session, "azure", ok, message)
        return {"ok": ok, "message": message}


@router.get("/datadog", response_model=DatadogSettingsView)
def get_datadog_settings() -> DatadogSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.datadog_settings_view(session)


@router.put("/datadog", response_model=DatadogSettingsView)
def put_datadog_settings(body: DatadogSettingsInput) -> DatadogSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_datadog_settings(session, body)
        return repository.datadog_settings_view(session)


@router.post("/datadog/test")
def test_datadog(body: DatadogSettingsInput | None = None) -> dict:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        cfg = body if body and (body.api_key or body.personal_access_token) else repository.load_datadog_settings(session)
        ok, message = test_datadog_credentials(cfg)
        repository.record_settings_test_result(session, "datadog", ok, message)
        return {"ok": ok, "message": message}
