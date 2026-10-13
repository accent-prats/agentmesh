"""Regression coverage for test_datadog_credentials' choice of validation
call. Found 2026-10-13: a real, valid Personal Access Token failed "Test
connection" with a clean 403 from Datadog. Root cause - /api/v1/validate
(AuthenticationApi.validate(), used for the classic API key) predates
Application keys/PATs entirely and never evaluates DD-APPLICATION-KEY at
all, so it structurally cannot authenticate a PAT, which this app places
in that exact slot (see datadog_auth.py). The fix routes a PAT through
GET /api/v2/current_user (UsersApi.get_current_user()) instead - Datadog's
documented PAT-compatible equivalent.

Nothing before this file exercised test_datadog_credentials directly -
test_settings_api.py only ever mocks it wholesale, and test_datadog_auth.py
covers the lower-level configure_datadog_client(), not this dispatch."""
from __future__ import annotations

import pytest

pytest.importorskip("datadog_api_client")  # optional `culprit[datadog]` extra - see pyproject.toml

from culprit.models.settings import DatadogSettingsInput
# Imported as a module, not `from ... import test_datadog_credentials` -
# pytest collects any module-level `test_`-prefixed callable as a test of
# its own, including an imported one, and tries to call it with no args.
from culprit.security import credential_test


class _FakeAttributes:
    email = "user@example.com"


class _FakeData:
    attributes = _FakeAttributes()


class _FakeCurrentUserResponse:
    data = _FakeData()


class _FakeValidateResponse:
    def __init__(self, valid):
        self.valid = valid


def test_a_pat_is_tested_via_get_current_user_not_validate(monkeypatch):
    calls = []

    class FakeUsersApi:
        def __init__(self, api_client):
            pass

        def get_current_user(self):
            calls.append("get_current_user")
            return _FakeCurrentUserResponse()

    class FakeAuthenticationApi:
        def __init__(self, api_client):
            pass

        def validate(self):
            # A PAT must never reach /api/v1/validate - it cannot
            # authenticate one (it never evaluates DD-APPLICATION-KEY).
            raise AssertionError("validate() must not be called for a PAT")

    monkeypatch.setattr("datadog_api_client.v2.api.users_api.UsersApi", FakeUsersApi)
    monkeypatch.setattr("datadog_api_client.v1.api.authentication_api.AuthenticationApi", FakeAuthenticationApi)

    ok, message = credential_test.test_datadog_credentials(DatadogSettingsInput(personal_access_token="a-real-pat"))

    assert ok is True
    assert calls == ["get_current_user"]
    assert "Personal Access Token" in message
    assert "user@example.com" in message


def test_a_classic_api_key_still_uses_validate(monkeypatch):
    """Regression guard: adding the PAT branch must not change behavior
    for the pre-existing API key path."""
    calls = []

    class FakeAuthenticationApi:
        def __init__(self, api_client):
            pass

        def validate(self):
            calls.append("validate")
            return _FakeValidateResponse(valid=True)

    class FakeUsersApi:
        def __init__(self, api_client):
            pass

        def get_current_user(self):
            raise AssertionError("get_current_user() must not be called for a classic API key")

    monkeypatch.setattr("datadog_api_client.v2.api.users_api.UsersApi", FakeUsersApi)
    monkeypatch.setattr("datadog_api_client.v1.api.authentication_api.AuthenticationApi", FakeAuthenticationApi)

    ok, message = credential_test.test_datadog_credentials(DatadogSettingsInput(api_key="a-real-key"))

    assert ok is True
    assert calls == ["validate"]
    assert "API key" in message
