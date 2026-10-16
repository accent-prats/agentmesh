"""Coverage for shared/src/llm/ - the multi-provider adapters that let an
app call something other than Anthropic through the same narrow,
Anthropic-shaped interface.

Verified against each provider's *documented* wire format via a fake
httpx transport (monkeypatching `httpx.post`), the same fakes-not-real-
SDKs rigor the rest of this platform applies elsewhere - not against live
credentials for each of the eight non-Anthropic providers. See
shared/src/llm/__init__.py's docstring.

The end-to-end proof that one of these can actually stand in for
Anthropic inside a real caller lives in
culprit/tests/test_llm_adapters_e2e.py instead, since it needs Culprit's
own pipeline/models - this file only depends on shared/src/llm itself.
"""
from __future__ import annotations

import httpx
import pytest

from shared.src.llm.catalog import PROVIDER_CATALOG
from shared.src.llm.factory import UnknownProvider, build_client
from shared.src.llm.gemini import GeminiClient, _strip_unsupported_schema_keys
from shared.src.llm.openai_compatible import OpenAICompatibleClient

_TOOL_SCHEMA = {
    "name": "submit_rca_finding",
    "description": "Submit the root-cause finding.",
    "input_schema": {
        "type": "object",
        "properties": {
            "cause_family": {"type": "string"},
            "nested": {"type": "object", "properties": {"x": {"type": "string"}}, "additionalProperties": False},
        },
        "required": ["cause_family"],
        "additionalProperties": False,
    },
    "strict": True,
}


class FakeHttpResponse:
    def __init__(self, json_data: dict, status_code: int = 200):
        self._json = json_data
        self.status_code = status_code
        self.text = str(json_data)
        self.request = httpx.Request("POST", "https://example.invalid")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=self.request, response=self)

    def json(self) -> dict:
        return self._json


# ── catalog ────────────────────────────────────────────────────────────────

class TestCatalog:
    def test_deepl_is_not_in_the_catalog(self):
        """DeepL is a translation API with no tool-calling concept at all -
        there is no applicable adapter for it, only an absence of one."""
        assert "deepl" not in PROVIDER_CATALOG

    def test_only_anthropic_has_no_base_url_requirement(self):
        assert PROVIDER_CATALOG["anthropic"].requires_base_url is False
        for provider, spec in PROVIDER_CATALOG.items():
            if provider != "anthropic":
                assert spec.requires_base_url is True, provider

    def test_local_providers_need_no_api_key(self):
        assert PROVIDER_CATALOG["ollama"].requires_api_key is False
        assert PROVIDER_CATALOG["lmstudio"].requires_api_key is False

    def test_default_model_is_always_a_listed_option_when_a_list_exists(self):
        """The Model dropdown falls back to "Other (custom)" for any
        value not in model_options - the catalog's own default_model
        must never be the thing that triggers that, or every provider
        would open on "Other" the first time an admin looks at it."""
        for provider, spec in PROVIDER_CATALOG.items():
            if spec.model_options:
                assert spec.default_model in spec.model_options, provider

    def test_lmstudio_has_no_curated_model_list(self):
        """Local, arbitrary model files - a fixed list would just be wrong
        for whatever the admin actually has loaded."""
        assert PROVIDER_CATALOG["lmstudio"].model_options == ()


# ── factory ────────────────────────────────────────────────────────────────

class TestFactory:
    def test_builds_a_real_anthropic_client(self):
        import anthropic

        client = build_client("anthropic", api_key="sk-ant-x")
        assert isinstance(client, anthropic.Anthropic)

    def test_builds_an_openai_compatible_client_with_the_catalog_default_url(self):
        client = build_client("openai", api_key="sk-x")
        assert isinstance(client, OpenAICompatibleClient)
        assert client.base_url == "https://api.openai.com/v1"
        assert client.is_azure is False

    def test_azure_openai_client_carries_deployment_and_api_version(self):
        client = build_client(
            "azure_openai", api_key="k", base_url="https://my-resource.openai.azure.com",
            api_version="2024-10-01", deployment="gpt5-deploy",
        )
        assert client.is_azure is True
        assert client.deployment == "gpt5-deploy"
        assert client.api_version == "2024-10-01"

    def test_builds_a_gemini_client(self):
        client = build_client("gemini", api_key="k")
        assert isinstance(client, GeminiClient)
        assert client.base_url == PROVIDER_CATALOG["gemini"].default_base_url

    def test_unknown_provider_raises(self):
        with pytest.raises(UnknownProvider):
            build_client("not-a-real-provider")


# ── OpenAICompatibleClient ─────────────────────────────────────────────────

class TestOpenAICompatibleClient:
    def _fake_post(self, monkeypatch, captured: dict, response_json: dict):
        def fake_post(url, *, headers, json, timeout):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            captured["timeout"] = timeout
            return FakeHttpResponse(response_json)

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.post", fake_post)

    def test_request_shape_forces_the_tool_call(self, monkeypatch):
        captured: dict = {}
        self._fake_post(monkeypatch, captured, {
            "choices": [{"message": {"tool_calls": [
                {"function": {"name": "submit_rca_finding", "arguments": '{"cause_family": "capacity"}'}}
            ]}}],
        })
        client = OpenAICompatibleClient(api_key="sk-x", base_url="https://api.openai.com/v1", supports_strict_tool_schema=True)

        response = client.messages.create(
            model="gpt-5", max_tokens=100, thinking=None, system="sys prompt",
            tools=[_TOOL_SCHEMA], messages=[{"role": "user", "content": "hi"}],
        )

        assert captured["url"] == "https://api.openai.com/v1/chat/completions"
        assert captured["headers"]["Authorization"] == "Bearer sk-x"
        assert captured["json"]["tool_choice"] == {"type": "function", "function": {"name": "submit_rca_finding"}}
        assert captured["json"]["tools"][0]["function"]["name"] == "submit_rca_finding"
        assert captured["json"]["tools"][0]["function"]["parameters"] == _TOOL_SCHEMA["input_schema"]
        assert captured["json"]["tools"][0]["function"]["strict"] is True
        assert captured["json"]["messages"][0] == {"role": "system", "content": "sys prompt"}

        assert response.content[0].name == "submit_rca_finding"
        assert response.content[0].input == '{"cause_family": "capacity"}'  # a raw string - the caller parses it

    def test_strict_is_omitted_when_the_provider_does_not_support_it(self, monkeypatch):
        captured: dict = {}
        self._fake_post(monkeypatch, captured, {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
        })
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.deepseek.com/v1", supports_strict_tool_schema=False)
        client.messages.create(model="deepseek-chat", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
        assert "strict" not in captured["json"]["tools"][0]["function"]

    def test_azure_endpoint_shape_uses_deployment_and_api_key_header(self, monkeypatch):
        captured: dict = {}
        self._fake_post(monkeypatch, captured, {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
        })
        client = OpenAICompatibleClient(
            api_key="azure-key", base_url="https://my-resource.openai.azure.com",
            is_azure=True, api_version="2024-10-01", deployment="gpt5-deploy",
        )
        client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        assert captured["url"] == (
            "https://my-resource.openai.azure.com/openai/deployments/gpt5-deploy"
            "/chat/completions?api-version=2024-10-01"
        )
        assert captured["headers"]["api-key"] == "azure-key"
        assert "Authorization" not in captured["headers"]

    def test_no_tool_call_returns_empty_content_not_a_crash(self, monkeypatch):
        captured: dict = {}
        self._fake_post(monkeypatch, captured, {"choices": [{"message": {}, "finish_reason": "stop"}]})
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")
        response = client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
        assert response.content == []
        assert response.stop_reason == "stop"

    def test_a_local_provider_omits_the_authorization_header_with_no_key(self, monkeypatch):
        captured: dict = {}
        self._fake_post(monkeypatch, captured, {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
        })
        client = OpenAICompatibleClient(api_key="", base_url="http://localhost:11434/v1")
        client.messages.create(model="llama3.1", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
        assert "Authorization" not in captured["headers"]

    def test_timeout_gives_the_read_phase_real_patience_but_fails_fast_on_connect(self, monkeypatch):
        """Found 2026-10-16 from a real production traceback: a flat 60s
        timeout applied to every phase equally, and it was specifically
        the read phase (waiting for a slow custom gateway to start
        streaming back a big completion) that failed, not connect. A
        genuinely dead endpoint must still fail fast."""
        captured: dict = {}
        self._fake_post(monkeypatch, captured, {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
        })
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")
        client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        timeout = captured["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.read >= 180.0
        assert timeout.connect <= 15.0

    def test_calls_are_traced_with_duration_and_outcome(self, monkeypatch, caplog):
        """Found 2026-10-16, tracing a real production timeout: this call
        had no logging of its own at all - the only way to know it was
        even the thing hanging was reading a raised exception's own
        traceback. Pins that the API key never leaks into the log (it
        lives in a header here, not the URL, but the log line must still
        never include it)."""
        captured: dict = {}
        self._fake_post(monkeypatch, captured, {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
        })
        client = OpenAICompatibleClient(api_key="sk-secret-dont-log-me", base_url="https://api.openai.com/v1")

        with caplog.at_level("INFO"):
            client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        messages = [r.message for r in caplog.records]
        assert any("calling" in m and "gpt-5" in m for m in messages)
        assert any("responded" in m and "200" in m for m in messages)
        assert not any("sk-secret-dont-log-me" in m for m in messages)

    def test_a_failed_call_is_logged_but_the_real_exception_still_propagates(self, monkeypatch, caplog):
        def fake_post(url, *, headers, json, timeout):
            raise httpx.ReadTimeout("The read operation timed out")

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.post", fake_post)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
                raised = None
            except httpx.ReadTimeout as exc:
                raised = exc

        assert raised is not None
        assert any(r.levelname == "WARNING" and "failed after" in r.message for r in caplog.records)


# ── GeminiClient ────────────────────────────────────────────────────────────

class TestGeminiClient:
    def test_strip_unsupported_schema_keys_removes_additional_properties_recursively(self):
        cleaned = _strip_unsupported_schema_keys(_TOOL_SCHEMA["input_schema"])
        assert "additionalProperties" not in cleaned
        assert "additionalProperties" not in cleaned["properties"]["nested"]
        assert cleaned["properties"]["nested"]["properties"] == {"x": {"type": "string"}}  # untouched otherwise

    def test_request_shape_forces_the_function_call(self, monkeypatch):
        captured: dict = {}

        def fake_post(url, *, json, timeout):
            captured["url"] = url
            captured["json"] = json
            return FakeHttpResponse({
                "candidates": [{"content": {"parts": [
                    {"functionCall": {"name": "submit_rca_finding", "args": {"cause_family": "capacity"}}}
                ]}}],
            })

        monkeypatch.setattr("shared.src.llm.gemini.httpx.post", fake_post)
        client = GeminiClient(api_key="g-key", base_url="https://generativelanguage.googleapis.com/v1beta")

        response = client.messages.create(
            model="gemini-2.5-pro", max_tokens=100, thinking=None, system="sys prompt",
            tools=[_TOOL_SCHEMA], messages=[{"role": "user", "content": "hi"}],
        )

        assert "key=g-key" in captured["url"]
        assert "gemini-2.5-pro" in captured["url"]
        decl = captured["json"]["tools"][0]["functionDeclarations"][0]
        assert decl["name"] == "submit_rca_finding"
        assert "additionalProperties" not in decl["parameters"]
        assert captured["json"]["tool_config"]["function_calling_config"] == {
            "mode": "ANY", "allowed_function_names": ["submit_rca_finding"],
        }

        assert response.content[0].name == "submit_rca_finding"
        assert response.content[0].input == {"cause_family": "capacity"}  # already a dict, unlike the OpenAI adapters

    def test_no_function_call_returns_empty_content_not_a_crash(self, monkeypatch):
        def fake_post(url, *, json, timeout):
            return FakeHttpResponse({"candidates": [{"content": {"parts": [{"text": "no tool call"}]}, "finishReason": "STOP"}]})

        monkeypatch.setattr("shared.src.llm.gemini.httpx.post", fake_post)
        client = GeminiClient(api_key="k", base_url="https://generativelanguage.googleapis.com/v1beta")
        response = client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
        assert response.content == []
        assert response.stop_reason == "STOP"

    def test_timeout_gives_the_read_phase_real_patience_but_fails_fast_on_connect(self, monkeypatch):
        """Same fix, same reason as OpenAICompatibleClient's own version of
        this test above - found in review 2026-10-16: Gemini is an
        independently-activatable catalog provider too, and was left with
        the identical flat-timeout bug while only the OpenAI-compatible
        family got fixed first."""
        captured: dict = {}

        def fake_post(url, *, json, timeout):
            captured["timeout"] = timeout
            return FakeHttpResponse({"candidates": [{"content": {"parts": [
                {"functionCall": {"name": "submit_rca_finding", "args": {}}}
            ]}}]})

        monkeypatch.setattr("shared.src.llm.gemini.httpx.post", fake_post)
        client = GeminiClient(api_key="k", base_url="https://generativelanguage.googleapis.com/v1beta")
        client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        timeout = captured["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.read >= 180.0
        assert timeout.connect <= 15.0

    def test_the_api_key_never_leaks_into_the_trace_log(self, monkeypatch, caplog):
        """Security-critical, not just a nice-to-have: unlike
        OpenAICompatibleClient, Gemini's API key lives in the URL's own
        query string (?key=...), not a header. Logging the real `url`
        variable as-is (an easy mistake to copy-paste from the OpenAI
        adapter's own tracing) would leak the credential straight into
        logs. This must stay true both on a successful call and a failed
        one - the API key must not appear in *any* log record."""
        def fake_post(url, *, json, timeout):
            return FakeHttpResponse({"candidates": [{"content": {"parts": [
                {"functionCall": {"name": "submit_rca_finding", "args": {}}}
            ]}}]})

        monkeypatch.setattr("shared.src.llm.gemini.httpx.post", fake_post)
        client = GeminiClient(api_key="AIzaSecretDontLogMe", base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("INFO"):
            client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        messages = [r.message for r in caplog.records]
        assert any("calling" in m and "gemini-2.5-pro" in m for m in messages)
        assert any("REDACTED" in m for m in messages)
        assert not any("AIzaSecretDontLogMe" in m for m in messages)

    def test_a_failed_call_does_not_leak_the_api_key_either(self, monkeypatch, caplog):
        def fake_post(url, *, json, timeout):
            raise httpx.ReadTimeout("The read operation timed out")

        monkeypatch.setattr("shared.src.llm.gemini.httpx.post", fake_post)
        client = GeminiClient(api_key="AIzaSecretDontLogMe", base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
                raised = None
            except httpx.ReadTimeout as exc:
                raised = exc

        assert raised is not None
        messages = [r.message for r in caplog.records]
        assert any(r.levelname == "WARNING" and "failed after" in r.message for r in caplog.records)
        assert not any("AIzaSecretDontLogMe" in m for m in messages)

    def test_an_http_status_error_does_not_leak_the_key_via_its_own_str(self, monkeypatch, caplog):
        """The sharper version of the test above: httpx.HTTPStatusError's
        own __str__ embeds the *full request URL* it was raised for -
        confirmed empirically (not assumed) that this includes Gemini's
        real API key, since it lives in the URL's query string. Logging
        `str(exc)` anywhere in the failure path - an easy thing to add
        when a status code would be genuinely useful in the log - would
        re-leak the key through the exception message itself, bypassing
        the safe_url redaction entirely. This is exactly why the warning
        log uses _safe_exc_summary(exc) (class + status code only) and
        never str(exc)."""
        real_key = "AIzaSecretDontLogMe"

        def fake_post(url, *, json, timeout):
            request = httpx.Request("POST", url)
            response = httpx.Response(401, request=request, json={"error": "unauthorized"})
            response.raise_for_status()  # raises httpx.HTTPStatusError, str() of which embeds `url` (with the real key)

        monkeypatch.setattr("shared.src.llm.gemini.httpx.post", fake_post)
        client = GeminiClient(api_key=real_key, base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
                raised = None
            except httpx.HTTPStatusError as exc:
                raised = exc
                assert real_key in str(exc)  # sanity check: confirms the exception really does embed the key

        assert raised is not None
        messages = [r.message for r in caplog.records]
        assert any("HTTPStatusError" in m and "401" in m for m in messages)
        assert not any(real_key in m for m in messages)
