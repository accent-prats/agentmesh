"""Builds the Azure credential every collector authenticates with, from
whatever's configured on the /culprit/settings screen (culprit/db/repository.py
`load_azure_settings`) - a service-principal `ClientSecretCredential` if a
tenant/client id and secret were saved, otherwise `DefaultAzureCredential`
(a managed identity, if this process happens to be running as one; `az
login` locally).

Every collector constructor accepts an already-built credential and
defers to this function only when none was given, so the demo/test
collectors (constructed with no arguments) keep working exactly as before
- nothing about this changes behavior unless a caller explicitly wires
settings-derived credentials through.
"""
from __future__ import annotations

from typing import Any

from culprit.models.settings import AzureSettingsInput


def build_credential(cfg: AzureSettingsInput | None = None) -> Any:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential

    if cfg and cfg.tenant_id and cfg.client_id and cfg.client_secret:
        return ClientSecretCredential(cfg.tenant_id, cfg.client_id, cfg.client_secret)
    return DefaultAzureCredential()
