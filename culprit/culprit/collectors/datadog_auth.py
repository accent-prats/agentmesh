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

Caveat worth knowing, not hidden behind a confident abstraction: PATs are
Preview on Datadog's side as of 2026-10, and the "PAT in appKeyAuth"
mechanism above only works against an endpoint that actually evaluates
DD-APPLICATION-KEY in the first place - most do (that's why `app_key` was
already a meaningful field here before PATs existed), but `/api/v1/validate`
specifically does not: it predates Application keys entirely and only
ever checks DD-API-KEY (confirmed via Datadog's own docs/curl example,
which sends no app-key header at all), so it can never authenticate a PAT
regardless of whether the PAT itself is good - found 2026-10-13 when a
real, valid PAT failed "Test connection" with a clean 403. See
credential_test.py::test_datadog_credentials for the fix (a different,
PAT-compatible validation call). Culprit's real collectors - v1 Metrics,
v1 Monitors, v2 Logs (see datadog_collector.py) - are all normal
data-query endpoints that do check DD-APPLICATION-KEY, so a PAT is
expected to work for all three the same way it does for `app_key` today;
this hasn't been exercised against a real Datadog org to confirm.
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
