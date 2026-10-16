"""Coverage for api/deps.py::get_rca_agent()'s provider-selection logic:
Portal lookup -> legacy env var -> scripted demo agent, with no default
provider baked in anywhere in that chain. The Portal call itself is
mocked at the `httpx.get` boundary - a real Portal deployment was not
part of this port; see api/deps.py's docstring for the actual contract
with portal/api/routers/ai_providers.py::get_resolved_active_provider."""
from __future__ import annotations

import dataclasses

import httpx
import pytest

import culprit.api.deps as deps_module
from culprit.demo.scripted_rca import ScriptedRCAAgent
from culprit.pipeline.rca_agent import DeepRCAAgent


class FakeHttpResponse:
    def __init__(self, json_data: dict, status_code: int = 200):
        self._json = json_data
        self.status_code = status_code
        self.request = httpx.Request("GET", "https://example.invalid")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=self.request, response=self)

    def json(self) -> dict:
        return self._json


def _with_portal_secret(monkeypatch, secret: str = "shared-secret"):
    monkeypatch.setattr(deps_module, "settings", dataclasses.replace(deps_module.settings, portal_jwt_secret=secret))


class TestNoPortalSecretConfigured:
    def test_skips_the_network_call_entirely(self, monkeypatch):
        """Standalone Culprit, no Portal deployed at all - CULPRIT_PORTAL_JWT_SECRET
        is blank by default, so there's nothing to sign a service token
        with and no point attempting the call."""
        monkeypatch.setattr(deps_module, "settings", dataclasses.replace(deps_module.settings, portal_jwt_secret=""))
        calls = []
        monkeypatch.setattr("httpx.get", lambda *a, **k: calls.append(1) or FakeHttpResponse({}))

        agent = deps_module.get_rca_agent()

        assert calls == []
        assert isinstance(agent, ScriptedRCAAgent)  # no ANTHROPIC_API_KEY in this test env either


class TestPortalHasAnActiveProvider:
    def test_builds_a_client_from_the_resolved_provider(self, monkeypatch):
        _with_portal_secret(monkeypatch)
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({
            "provider": "openai", "api_key": "sk-x", "base_url": "https://api.openai.com/v1",
            "model": "gpt-5", "api_version": "", "deployment": "",
        }))

        agent = deps_module.get_rca_agent()

        assert isinstance(agent, DeepRCAAgent)
        assert agent.model == "gpt-5"

    def test_logs_which_provider_and_model_it_picked(self, monkeypatch, caplog):
        """Found 2026-10-16, tracing a real production timeout: this
        success path had no logging of its own - the only visible signal
        anywhere in get_rca_agent() was the scripted-fallback warning, so
        there was no way to confirm from logs alone which provider/model
        a given run actually used. Also pins that the API key itself
        never appears in the log message."""
        _with_portal_secret(monkeypatch)
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({
            "provider": "deepseek", "api_key": "sk-secret-dont-log-me", "base_url": "https://api.siemens.com/llm/v1",
            "model": "deepseek-v4.1-flash", "api_version": "", "deployment": "",
        }))

        with caplog.at_level("INFO"):
            deps_module.get_rca_agent()

        messages = [r.message for r in caplog.records]
        assert any("deepseek" in m and "deepseek-v4.1-flash" in m for m in messages)
        assert not any("sk-secret-dont-log-me" in m for m in messages)

    def test_falls_back_to_the_catalog_default_model_when_none_is_saved(self, monkeypatch):
        _with_portal_secret(monkeypatch)
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({
            "provider": "anthropic", "api_key": "sk-ant-x", "base_url": "", "model": "", "api_version": "", "deployment": "",
        }))

        agent = deps_module.get_rca_agent()

        assert isinstance(agent, DeepRCAAgent)
        assert agent.model == "claude-opus-5"


class TestPortalHasNothingConfigured:
    def test_an_empty_provider_falls_back_to_legacy_env_var(self, monkeypatch):
        """No admin has ever picked a provider on the Portal AI Providers
        screen - Portal reports provider="" (no default), and this must not
        invent one; ANTHROPIC_API_KEY, if set, is the fallback."""
        _with_portal_secret(monkeypatch)
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({"provider": ""}))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-legacy")

        agent = deps_module.get_rca_agent()

        assert isinstance(agent, DeepRCAAgent)
        assert agent.model == deps_module.settings.rca_model

    def test_env_var_fallback_is_logged_too(self, monkeypatch, caplog):
        _with_portal_secret(monkeypatch)
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({"provider": ""}))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-legacy")

        with caplog.at_level("INFO"):
            deps_module.get_rca_agent()

        assert any("ANTHROPIC_API_KEY" in r.message and "env fallback" in r.message for r in caplog.records)

    def test_an_empty_provider_and_no_env_var_falls_back_to_the_scripted_agent(self, monkeypatch):
        _with_portal_secret(monkeypatch)
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({"provider": ""}))
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)

        agent = deps_module.get_rca_agent()

        assert isinstance(agent, ScriptedRCAAgent)

    def test_falling_back_to_the_scripted_agent_logs_a_loud_warning(self, monkeypatch, caplog):
        """Found 2026-10-16: this fallback used to have zero logging of
        its own - a real deployment with nothing configured would
        silently get the scripted demo stand-in (which doesn't read
        collected evidence at all) for every run, forever, with nothing
        in the logs to explain why RCA quality never improved no matter
        what evidence-collection fixes landed. Every real caller
        (pipeline/live_run.py, api/routes_runs.py's demo trigger) must
        get this warning so it's visible wherever Culprit's own logs are
        actually read, not just discoverable by reading this source file."""
        _with_portal_secret(monkeypatch)
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({"provider": ""}))
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)

        with caplog.at_level("WARNING"):
            deps_module.get_rca_agent()

        assert any("SCRIPTED demo RCA agent" in r.message for r in caplog.records)


class TestPortalUnreachable:
    def test_a_network_failure_falls_back_gracefully_rather_than_raising(self, monkeypatch):
        _with_portal_secret(monkeypatch)

        def fake_get(*args, **kwargs):
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr("httpx.get", fake_get)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-legacy")

        agent = deps_module.get_rca_agent()

        assert isinstance(agent, DeepRCAAgent)

    def test_an_http_error_status_falls_back_gracefully(self, monkeypatch):
        _with_portal_secret(monkeypatch)
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({}, status_code=500))
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)

        agent = deps_module.get_rca_agent()

        assert isinstance(agent, ScriptedRCAAgent)
