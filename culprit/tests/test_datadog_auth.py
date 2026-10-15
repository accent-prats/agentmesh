"""Unit coverage for datadog_auth.py::configure_datadog_client - the single
place both the real DatadogCollector and the settings screen's "Test
connection" button build their datadog_api_client Configuration from.

Mirrors test_azure_auth.py's shape and reasoning: never exercised anywhere
else in the suite (test_settings_api.py's Datadog tests mock
test_datadog_credentials wholesale), added 2026-10-11 alongside Personal
Access Token support to prove the PAT-vs-classic branching actually
selects the right credential rather than just being documented to."""
from __future__ import annotations

import pytest

pytest.importorskip("datadog_api_client")  # optional `culprit[datadog]` extra - see pyproject.toml

from culprit.collectors.datadog_auth import configure_datadog_client, datadog_is_configured
from culprit.models.settings import DatadogSettingsInput


def test_no_config_at_all_returns_an_unconfigured_client():
    configuration = configure_datadog_client(None)
    assert configuration.api_key.get("apiKeyAuth") is None
    assert configuration.api_key.get("appKeyAuth") is None


def test_a_pat_is_placed_in_both_api_key_and_app_key_auth_slots():
    """The SDK has no distinct Bearer/PAT scheme - a PAT is configured by
    putting it in the same appKeyAuth slot an Application key would
    occupy (Datadog's own documented migration path), mirrored into
    apiKeyAuth too since the SDK needs something non-empty there to send
    the header at all."""
    cfg = DatadogSettingsInput(personal_access_token="a-real-pat", site="datadoghq.eu")
    configuration = configure_datadog_client(cfg)

    assert configuration.api_key["apiKeyAuth"] == "a-real-pat"
    assert configuration.api_key["appKeyAuth"] == "a-real-pat"
    assert configuration.server_variables["site"] == "datadoghq.eu"


def test_a_pat_takes_priority_over_a_classic_key_pair_if_both_are_somehow_set():
    """Shouldn't be reachable via the settings screen's toggle (it always
    blanks the inactive side), but if it ever is, the PAT branch must win
    deterministically rather than silently picking one at random."""
    cfg = DatadogSettingsInput(personal_access_token="a-real-pat", api_key="an-api-key", app_key="an-app-key")
    configuration = configure_datadog_client(cfg)

    assert configuration.api_key["apiKeyAuth"] == "a-real-pat"
    assert configuration.api_key["appKeyAuth"] == "a-real-pat"


def test_classic_api_key_and_app_key_without_a_pat():
    cfg = DatadogSettingsInput(api_key="an-api-key", app_key="an-app-key", site="us3.datadoghq.com")
    configuration = configure_datadog_client(cfg)

    assert configuration.api_key["apiKeyAuth"] == "an-api-key"
    assert configuration.api_key["appKeyAuth"] == "an-app-key"
    assert configuration.server_variables["site"] == "us3.datadoghq.com"


def test_api_key_without_an_app_key_still_configures_apiKeyAuth_only():
    cfg = DatadogSettingsInput(api_key="an-api-key")
    configuration = configure_datadog_client(cfg)

    assert configuration.api_key["apiKeyAuth"] == "an-api-key"
    assert configuration.api_key.get("appKeyAuth") is None


def test_blank_settings_object_configures_nothing():
    """Settings exist (a record was saved) but everything's blank - falls
    through to the SDK's own env-var resolution, same as cfg=None."""
    configuration = configure_datadog_client(DatadogSettingsInput())
    assert configuration.api_key.get("apiKeyAuth") is None
    assert configuration.api_key.get("appKeyAuth") is None


# ── datadog_is_configured ───────────────────────────────────────────────────
# Used by api/deps.py::build_live_collectors to decide whether to register
# the Datadog collector at all - found 2026-10-15: registering it
# unconditionally meant every machine, every run got 2-3 Datadog-shaped
# collection_gaps entries in any deployment that never configured it,
# indistinguishable from an intermittent real failure.

def test_no_config_and_no_env_var_is_not_configured(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    assert datadog_is_configured(None) is False
    assert datadog_is_configured(DatadogSettingsInput()) is False


def test_a_saved_pat_counts_as_configured(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    assert datadog_is_configured(DatadogSettingsInput(personal_access_token="a-real-pat")) is True


def test_a_saved_api_key_counts_as_configured(monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    assert datadog_is_configured(DatadogSettingsInput(api_key="an-api-key")) is True


def test_the_env_var_fallback_alone_still_counts_as_configured(monkeypatch):
    """A deployment that only ever used DD_API_KEY/DD_APP_KEY (never
    touched the settings screen) must not get wrongly skipped - this is
    configure_datadog_client's own documented fallback path, still real."""
    monkeypatch.setenv("DD_API_KEY", "env-key")
    assert datadog_is_configured(None) is True
    assert datadog_is_configured(DatadogSettingsInput()) is True
