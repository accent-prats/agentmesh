"""Azure and Datadog connection settings - what the /culprit/settings
screen reads and writes.

Two shapes per provider: an `*Input` the settings form submits (may
contain a secret in plain text over the wire, same as any credentials
form), and a `*View` the API returns afterwards, which never echoes a
secret back - only whether one is configured, plus the last
connection-test result.

The deep RCA agent's own AI provider (which model it calls) is a
platform-level, admin-managed setting owned by the Portal instead - see
`portal/db.py::AIProviderSetting` and `portal/api/routers/ai_providers.py`
- so it isn't modeled here at all.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AzureSettingsInput(BaseModel):
    subscription_ids: list[str] = Field(default_factory=list)
    log_analytics_workspace_id: str = ""
    tenant_id: str = ""
    client_id: str = ""
    # Blank on an update means "leave the currently-stored secret alone" -
    # routes_settings.py is what implements that merge; this model itself
    # doesn't know whether blank means "unset" or "unchanged".
    client_secret: str = ""
    # The one deliberate exception to the rule above: the settings screen's
    # "Managed identity" radio sets this to actually forget a previously-
    # saved secret when the admin explicitly switches away from a service
    # principal, instead of leaving it as an orphaned, unused ciphertext
    # (found 2026-10-10 - harmless functionally since build_credential never
    # reads it once tenant/client are blank, but confusing to leave behind).
    # A blank client_secret alone must never trigger this on its own, or
    # the anti-lockout protection above stops meaning anything.
    clear_credentials: bool = False


class AzureSettingsView(BaseModel):
    subscription_ids: list[str] = Field(default_factory=list)
    log_analytics_workspace_id: str = ""
    tenant_id: str = ""
    client_id: str = ""
    client_secret_configured: bool = False
    configured: bool = False
    last_tested_at: datetime | None = None
    last_test_ok: bool | None = None
    last_test_message: str = ""


class DatadogSettingsInput(BaseModel):
    site: str = "datadoghq.com"
    api_key: str = ""
    app_key: str = ""


class DatadogSettingsView(BaseModel):
    site: str = "datadoghq.com"
    api_key_configured: bool = False
    app_key_configured: bool = False
    configured: bool = False
    last_tested_at: datetime | None = None
    last_test_ok: bool | None = None
    last_test_message: str = ""
