"""Coverage for shared/src/llm/credential_test.py - the "Test connection"
button's real (but mocked-at-the-HTTP-boundary) live call per provider
kind. Not exercised by test_llm_adapters.py, which only covers the
request-building adapters themselves."""
from __future__ import annotations

import httpx

from shared.src.llm.credential_test import test_ai_provider_credentials as check_provider_credentials


class FakeHttpResponse:
    def __init__(self, json_data: dict, status_code: int = 200, text: str = ""):
        self._json = json_data
        self.status_code = status_code
        self.text = text or str(json_data)
        self.request = httpx.Request("GET", "https://example.invalid")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=self.request, response=self)

    def json(self) -> dict:
        return self._json


class FakeModelInfo:
    def __init__(self, id_: str):
        self.id = id_


class FakeModelsPage:
    def __init__(self, data):
        self.data = data


class FakeAnthropicClient:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.models = self

    def list(self, *, limit):
        return FakeModelsPage([FakeModelInfo("claude-opus-5")])


def test_unknown_provider_is_reported_not_raised():
    ok, message = check_provider_credentials("not-a-real-provider", api_key="x", base_url="", model="")
    assert ok is False
    assert "Unknown AI provider" in message


def test_missing_api_key_is_reported_before_any_network_call(monkeypatch):
    calls = []
    monkeypatch.setattr("httpx.get", lambda *a, **k: calls.append(1))
    monkeypatch.setattr("httpx.post", lambda *a, **k: calls.append(1))

    ok, message = check_provider_credentials("openai", api_key="", base_url="", model="")

    assert ok is False
    assert "No API key" in message
    assert calls == []


def test_missing_endpoint_is_reported_for_a_provider_that_needs_one():
    ok, message = check_provider_credentials("azure_openai", api_key="k", base_url="", model="")
    assert ok is False
    assert "No endpoint configured" in message


class TestAnthropic:
    def test_success_reports_a_reachable_model_catalog(self, monkeypatch):
        monkeypatch.setattr("anthropic.Anthropic", FakeAnthropicClient)

        ok, message = check_provider_credentials("anthropic", api_key="sk-ant-x", base_url="", model="")

        assert ok is True
        assert "claude-opus-5" in message

    def test_no_base_url_is_required_for_anthropic(self, monkeypatch):
        """Anthropic has no endpoint concept - the earlier no-endpoint
        check must not fire for it even though base_url is always blank."""
        monkeypatch.setattr("anthropic.Anthropic", FakeAnthropicClient)
        ok, _ = check_provider_credentials("anthropic", api_key="sk-ant-x", base_url="", model="")
        assert ok is True

    def test_sdk_failure_is_reported_not_raised(self, monkeypatch):
        class FailingClient:
            def __init__(self, api_key=None):
                self.models = self

            def list(self, *, limit):
                raise RuntimeError("401 unauthorized")

        monkeypatch.setattr("anthropic.Anthropic", FailingClient)
        ok, message = check_provider_credentials("anthropic", api_key="bad-key", base_url="", model="")
        assert ok is False
        assert "401 unauthorized" in message


class TestGemini:
    def test_success_reports_the_model_count(self, monkeypatch):
        captured = {}

        def fake_get(url, *, params, timeout):
            captured["url"] = url
            captured["params"] = params
            return FakeHttpResponse({"models": [{"name": "gemini-2.5-pro"}, {"name": "gemini-2.5-flash"}]})

        monkeypatch.setattr("httpx.get", fake_get)
        ok, message = check_provider_credentials(
            "gemini", api_key="g-key", base_url="https://generativelanguage.googleapis.com/v1beta", model="",
        )

        assert ok is True
        assert "2 model" in message
        assert captured["params"] == {"key": "g-key"}

    def test_http_error_status_is_reported(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeHttpResponse({}, status_code=401, text="invalid key"))
        ok, message = check_provider_credentials(
            "gemini", api_key="bad", base_url="https://generativelanguage.googleapis.com/v1beta", model="",
        )
        assert ok is False
        assert "HTTP 401" in message
        assert "invalid key" in message


class TestOpenAICompatible:
    def test_success_completes_a_minimal_request(self, monkeypatch):
        captured = {}

        def fake_post(url, *, headers, json, timeout):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return FakeHttpResponse({"choices": [{"message": {"content": "hi"}}]})

        monkeypatch.setattr("httpx.post", fake_post)
        ok, message = check_provider_credentials(
            "openai", api_key="sk-x", base_url="https://api.openai.com/v1", model="gpt-5",
        )

        assert ok is True
        assert captured["url"] == "https://api.openai.com/v1/chat/completions"
        assert captured["headers"]["Authorization"] == "Bearer sk-x"
        assert captured["json"]["max_tokens"] == 1

    def test_azure_uses_the_deployment_url_shape_and_api_key_header(self, monkeypatch):
        captured = {}

        def fake_post(url, *, headers, json, timeout):
            captured["url"] = url
            captured["headers"] = headers
            return FakeHttpResponse({"choices": []})

        monkeypatch.setattr("httpx.post", fake_post)
        ok, _ = check_provider_credentials(
            "azure_openai", api_key="azure-key", base_url="https://my-resource.openai.azure.com",
            model="gpt-5", api_version="2024-10-01", deployment="gpt5-deploy",
        )

        assert ok is True
        assert captured["url"] == (
            "https://my-resource.openai.azure.com/openai/deployments/gpt5-deploy"
            "/chat/completions?api-version=2024-10-01"
        )
        assert captured["headers"]["api-key"] == "azure-key"
        assert "Authorization" not in captured["headers"]

    def test_a_local_provider_with_no_key_omits_the_authorization_header(self, monkeypatch):
        captured = {}

        def fake_post(url, *, headers, json, timeout):
            captured["headers"] = headers
            return FakeHttpResponse({"choices": []})

        monkeypatch.setattr("httpx.post", fake_post)
        ok, _ = check_provider_credentials("ollama", api_key="", base_url="http://localhost:11434/v1", model="llama3.1")

        assert ok is True
        assert "Authorization" not in captured["headers"]

    def test_http_error_status_is_reported(self, monkeypatch):
        monkeypatch.setattr("httpx.post", lambda *a, **k: FakeHttpResponse({}, status_code=500, text="server error"))
        ok, message = check_provider_credentials(
            "openai", api_key="sk-x", base_url="https://api.openai.com/v1", model="gpt-5",
        )
        assert ok is False
        assert "HTTP 500" in message
