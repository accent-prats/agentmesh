"""Builds the datadog_api_client Configuration every Datadog collector and
the settings screen's "Test connection" button authenticates with, from
whatever's configured on /culprit/settings (culprit/db/repository.py
`load_datadog_settings`).

Two mutually exclusive credential shapes - a Personal Access Token (PAT)
if one was saved, otherwise the classic API key + Application key pair.
Datadog's own PAT docs document exactly this swap: a valid PAT sent in the
`dd-application-key` header authenticates alone, and `dd-api-key` is
optional and its value is not evaluated -
https://docs.datadoghq.com/account_management/personal-access-tokens/.
The datadog-api-client SDK has no distinct Bearer/PAT security scheme of
its own - only `apiKeyAuth`/`appKeyAuth` - so a PAT is configured by
putting it in the exact same `appKeyAuth` slot an Application key would
otherwise occupy (also mirrored into `apiKeyAuth`, since Datadog says
that header's value isn't evaluated once a valid PAT is present, but the
SDK still needs something non-empty there to actually send the header).
This is Datadog's own documented migration path for integrations that
haven't changed their auth code, not a workaround invented here.

Caveat worth knowing, not hidden behind a confident abstraction: Datadog's
PAT docs and examples are all v2 API calls, and PATs are Preview as of
2026-10. Culprit's real collectors call v1 Metrics/Monitors APIs and a v2
Logs API (see datadog_collector.py) - a PAT is confirmed by Datadog's own
docs to work for the v2 Logs call, but v1 compatibility for metrics/
monitor-state collection is not documented either way. A PAT that passes
"Test connection" (a v1 call, see credential_test.py) but still fails on
a real metrics/monitor collection - or vice versa - would point at this
exact v1/v2 gap rather than a bad token.
"""
from __future__ import annotations

from typing import Any

from culprit.models.settings import DatadogSettingsInput


def configure_datadog_client(cfg: DatadogSettingsInput | None) -> Any:
    from datadog_api_client import Configuration

    configuration = Configuration()
    if not cfg:
        return configuration  # no settings saved at all - env var fallback, unchanged from before

    if cfg.personal_access_token:
        configuration.api_key["apiKeyAuth"] = cfg.personal_access_token
        configuration.api_key["appKeyAuth"] = cfg.personal_access_token
        configuration.server_variables["site"] = cfg.site or "datadoghq.com"
    elif cfg.api_key:
        configuration.api_key["apiKeyAuth"] = cfg.api_key
        if cfg.app_key:
            configuration.api_key["appKeyAuth"] = cfg.app_key
        configuration.server_variables["site"] = cfg.site or "datadoghq.com"

    return configuration
