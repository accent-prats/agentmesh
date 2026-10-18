"""Coverage for shared/src/llm/ - the multi-provider adapters that let an
app call something other than Anthropic through the same narrow,
Anthropic-shaped interface.

Verified against each provider's *documented* wire format via a fake
httpx transport (monkeypatching `httpx.stream`, since both adapters now
stream the response - see FakeStream's own docstring for why), the same
fakes-not-real-SDKs rigor the rest of this platform applies elsewhere -
not against live credentials for each of the eight non-Anthropic
providers. See shared/src/llm/__init__.py's docstring.

The end-to-end proof that one of these can actually stand in for
Anthropic inside a real caller lives in
culprit/tests/test_llm_adapters_e2e.py instead, since it needs Culprit's
own pipeline/models - this file only depends on shared/src/llm itself.
"""
from __future__ import annotations

import time

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
    """Stands in for the httpx.Response yielded by `with httpx.stream(...)
    as response:`. `.read()` is a no-op (the fake body is already fully in
    memory), matching real httpx's own contract that `.json()`/`.content`
    keep working after `.read()` has been called inside the `with` block,
    even once it's exited (confirmed empirically against a real
    httpx.Response, not assumed)."""
    def __init__(self, json_data: dict, status_code: int = 200):
        self._json = json_data
        self.status_code = status_code
        self.text = str(json_data)
        self.request = httpx.Request("POST", "https://example.invalid")

    def read(self) -> None:
        pass

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=self.request, response=self)

    def json(self) -> dict:
        return self._json


class FakeStream:
    """Stands in for the context manager `httpx.stream(...)` returns. The
    real one does the network connect/send/wait-for-headers on `__enter__`
    and only reads the body when `.read()` is explicitly called - exactly
    the two-phase split this module's own time-to-first-byte logging
    depends on, so a test needs to be able to simulate each phase failing
    (or taking time) independently:

    - `enter_exc`: raised from `__enter__` - models a gateway that never
      responds at all (no headers ever arrive).
    - `read_exc`: raised from `.read()` - models a gateway that DID send
      headers/status but then stalled or failed partway through the body.
    - `sleep_before_enter` / `sleep_before_read`: models a slow phase for
      heartbeat-logging tests, without needing a real multi-second wait.
    """
    def __init__(
        self, response: FakeHttpResponse | None = None, *,
        enter_exc: BaseException | None = None, read_exc: BaseException | None = None,
        sleep_before_enter: float = 0.0, sleep_before_read: float = 0.0,
    ):
        self._response = response
        self._enter_exc = enter_exc
        self._read_exc = read_exc
        self._sleep_before_enter = sleep_before_enter
        self._sleep_before_read = sleep_before_read

    def __enter__(self):
        if self._sleep_before_enter:
            time.sleep(self._sleep_before_enter)
        if self._enter_exc is not None:
            raise self._enter_exc
        response = self._response
        original_read = response.read
        sleep_before_read, read_exc = self._sleep_before_read, self._read_exc

        def read():
            if sleep_before_read:
                time.sleep(sleep_before_read)
            if read_exc is not None:
                raise read_exc
            return original_read()

        response.read = read
        return response

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


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
    def _fake_stream(self, monkeypatch, captured: dict, response_json: dict, status_code: int = 200):
        def fake_stream(method, url, *, headers, json, timeout):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            captured["timeout"] = timeout
            return FakeStream(FakeHttpResponse(response_json, status_code))

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)

    def test_request_shape_forces_the_tool_call(self, monkeypatch):
        captured: dict = {}
        self._fake_stream(monkeypatch, captured, {
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
        self._fake_stream(monkeypatch, captured, {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
        })
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.deepseek.com/v1", supports_strict_tool_schema=False)
        client.messages.create(model="deepseek-chat", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
        assert "strict" not in captured["json"]["tools"][0]["function"]

    def test_azure_endpoint_shape_uses_deployment_and_api_key_header(self, monkeypatch):
        captured: dict = {}
        self._fake_stream(monkeypatch, captured, {
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
        self._fake_stream(monkeypatch, captured, {"choices": [{"message": {}, "finish_reason": "stop"}]})
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")
        response = client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
        assert response.content == []
        assert response.stop_reason == "stop"

    def test_a_local_provider_omits_the_authorization_header_with_no_key(self, monkeypatch):
        captured: dict = {}
        self._fake_stream(monkeypatch, captured, {
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
        self._fake_stream(monkeypatch, captured, {
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
        self._fake_stream(monkeypatch, captured, {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
        })
        client = OpenAICompatibleClient(api_key="sk-secret-dont-log-me", base_url="https://api.openai.com/v1")

        with caplog.at_level("INFO"):
            client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        messages = [r.message for r in caplog.records]
        assert any("calling" in m and "gpt-5" in m for m in messages)
        assert any("fully responded" in m and "200" in m for m in messages)
        assert not any("sk-secret-dont-log-me" in m for m in messages)

    def test_a_failed_call_is_logged_but_the_real_exception_still_propagates(self, monkeypatch, caplog):
        def fake_stream(method, url, *, headers, json, timeout):
            return FakeStream(enter_exc=httpx.ReadTimeout("The read operation timed out"))

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
                raised = None
            except httpx.ReadTimeout as exc:
                raised = exc

        assert raised is not None
        assert any(r.levelname == "WARNING" and "failed after" in r.message for r in caplog.records)

    def test_a_slow_call_logs_heartbeats_while_still_waiting(self, monkeypatch, caplog):
        """Found 2026-10-17 from a real production run: the service log
        showed "calling ..." once, then nothing at all for the entire
        ~10-minute read timeout before the eventual failure - a slow call
        and a hung process looked identical from the logs alone."""
        monkeypatch.setattr("shared.src.llm.openai_compatible._HEARTBEAT_INTERVAL_SECONDS", 0.05)

        def fake_stream(method, url, *, headers, json, timeout):
            return FakeStream(FakeHttpResponse({
                "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
            }), sleep_before_enter=0.2)

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("INFO"):
            client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        heartbeats = [r.message for r in caplog.records if "still waiting" in r.message]
        assert len(heartbeats) >= 2
        assert all("gpt-5" in m for m in heartbeats)

    def test_heartbeats_stop_once_a_call_finally_fails(self, monkeypatch, caplog):
        """The heartbeat must cover the whole wait leading up to a timeout,
        not just a successful call - that's the exact gap this was built
        to close."""
        monkeypatch.setattr("shared.src.llm.openai_compatible._HEARTBEAT_INTERVAL_SECONDS", 0.05)

        def fake_stream(method, url, *, headers, json, timeout):
            return FakeStream(enter_exc=httpx.ReadTimeout("The read operation timed out"), sleep_before_enter=0.15)

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("INFO"):
            try:
                client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.ReadTimeout:
                pass

        heartbeats = [r.message for r in caplog.records if "still waiting" in r.message]
        assert len(heartbeats) >= 1

    def test_logs_time_to_first_byte_separately_from_full_response_time(self, monkeypatch, caplog):
        """Found 2026-10-17: a flat httpx.post() call couldn't tell "the
        gateway never responded at all" apart from "it responded and then
        stalled partway through the body" - both just looked like the
        same ReadTimeout after the same full window. httpx.stream()
        returns as soon as headers arrive, before the body is read, so a
        genuinely-answering-but-slow call now gets its own log line."""
        def fake_stream(method, url, *, headers, json, timeout):
            return FakeStream(FakeHttpResponse({
                "choices": [{"message": {"tool_calls": [{"function": {"name": "submit_rca_finding", "arguments": "{}"}}]}}],
            }))

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("INFO"):
            client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        messages = [r.message for r in caplog.records]
        assert any("sent response headers" in m and "200" in m for m in messages)
        assert any("fully responded" in m and "200" in m for m in messages)

    def test_a_timeout_before_any_response_headers_never_logs_ttfb(self, monkeypatch, caplog):
        """The gateway never responding at all - the real bug this was
        built to diagnose - must NOT produce a "sent response headers"
        line. That absence is itself the diagnostic signal."""
        def fake_stream(method, url, *, headers, json, timeout):
            return FakeStream(enter_exc=httpx.ReadTimeout("The read operation timed out"))

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("INFO"):
            try:
                client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.ReadTimeout:
                pass

        messages = [r.message for r in caplog.records]
        assert not any("sent response headers" in m for m in messages)
        assert any(r.levelname == "WARNING" and "failed after" in r.message for r in caplog.records)

    def test_a_timeout_while_reading_the_body_still_logs_ttfb_first(self, monkeypatch, caplog):
        """The opposite case: the gateway DID start responding (headers
        arrived) but then stalled or failed partway through the body -
        this must still log the TTFB line before the eventual failure,
        distinguishing it from the "nothing ever came back" case above."""
        def fake_stream(method, url, *, headers, json, timeout):
            return FakeStream(FakeHttpResponse({"choices": []}), read_exc=httpx.ReadTimeout("The read operation timed out"))

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("INFO"):
            try:
                client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.ReadTimeout:
                pass

        messages = [r.message for r in caplog.records]
        assert any("sent response headers" in m for m in messages)
        assert any(r.levelname == "WARNING" and "failed after" in r.message for r in caplog.records)

    def test_an_immediate_4xx_logs_the_response_body(self, monkeypatch, caplog):
        """Found 2026-10-18 from a real production run: two different
        providers each failed fast (400, 403) with no further information
        at all - the bare status code alone gives no way to tell "prompt
        too long" from "a schema the provider's strict mode rejects" from
        "the gateway blocked the request outright". The response body is
        the provider's own explanation and is the single most useful
        thing still missing from this log line."""
        def fake_stream(method, url, *, headers, json, timeout):
            request = httpx.Request("POST", url)
            response = httpx.Response(
                400, request=request,
                json={"error": {"message": "maximum context length exceeded", "type": "invalid_request_error"}},
            )
            return FakeStream(response)

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
                raised = None
            except httpx.HTTPStatusError as exc:
                raised = exc

        assert raised is not None
        messages = [r.message for r in caplog.records]
        assert any("maximum context length exceeded" in m for m in messages)

    def test_the_api_key_is_redacted_even_from_an_echoed_error_body(self, monkeypatch, caplog):
        """Defensive, not just theoretical: a proxy/WAF-generated error page
        can echo back the request it blocked, including a header value, in
        its own error body - unlikely for OpenAICompatibleClient (the key
        lives in a header, not the URL this client logs), but the same
        redaction is applied here regardless, on the same "never trust a
        provider's output to be secret-free" principle this module already
        applies to the request side."""
        real_key = "sk-secret-dont-log-me"

        def fake_stream(method, url, *, headers, json, timeout):
            request = httpx.Request("POST", url)
            response = httpx.Response(403, request=request, json={"error": f"blocked request with key {real_key}"})
            return FakeStream(response)

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key=real_key, base_url="https://api.openai.com/v1")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.HTTPStatusError:
                pass

        messages = [r.message for r in caplog.records]
        assert any("blocked request with key" in m for m in messages)
        assert not any(real_key in m for m in messages)
        assert any("[REDACTED]" in m for m in messages)

    def test_a_trivially_short_api_key_does_not_mangle_unrelated_text(self, monkeypatch, caplog):
        """Found while writing this very feature's own tests: a one-letter
        api_key like "k" (a common throwaway test placeholder, and in
        principle a pathologically short real one) also matches the "k" in
        ordinary words like "blocked" - blindly replacing every occurrence
        would corrupt the message instead of protecting anything real."""
        def fake_stream(method, url, *, headers, json, timeout):
            request = httpx.Request("POST", url)
            response = httpx.Response(403, request=request, json={"error": "request blocked by policy"})
            return FakeStream(response)

        monkeypatch.setattr("shared.src.llm.openai_compatible.httpx.stream", fake_stream)
        client = OpenAICompatibleClient(api_key="k", base_url="https://api.openai.com/v1")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gpt-5", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.HTTPStatusError:
                pass

        messages = [r.message for r in caplog.records]
        assert any("request blocked by policy" in m for m in messages)
        assert not any("[REDACTED]" in m for m in messages)


# ── GeminiClient ────────────────────────────────────────────────────────────

class TestGeminiClient:
    def test_strip_unsupported_schema_keys_removes_additional_properties_recursively(self):
        cleaned = _strip_unsupported_schema_keys(_TOOL_SCHEMA["input_schema"])
        assert "additionalProperties" not in cleaned
        assert "additionalProperties" not in cleaned["properties"]["nested"]
        assert cleaned["properties"]["nested"]["properties"] == {"x": {"type": "string"}}  # untouched otherwise

    def test_request_shape_forces_the_function_call(self, monkeypatch):
        captured: dict = {}

        def fake_stream(method, url, *, json, timeout):
            captured["url"] = url
            captured["json"] = json
            return FakeStream(FakeHttpResponse({
                "candidates": [{"content": {"parts": [
                    {"functionCall": {"name": "submit_rca_finding", "args": {"cause_family": "capacity"}}}
                ]}}],
            }))

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
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
        def fake_stream(method, url, *, json, timeout):
            return FakeStream(FakeHttpResponse({"candidates": [{"content": {"parts": [{"text": "no tool call"}]}, "finishReason": "STOP"}]}))

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
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

        def fake_stream(method, url, *, json, timeout):
            captured["timeout"] = timeout
            return FakeStream(FakeHttpResponse({"candidates": [{"content": {"parts": [
                {"functionCall": {"name": "submit_rca_finding", "args": {}}}
            ]}}]}))

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
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
        def fake_stream(method, url, *, json, timeout):
            return FakeStream(FakeHttpResponse({"candidates": [{"content": {"parts": [
                {"functionCall": {"name": "submit_rca_finding", "args": {}}}
            ]}}]}))

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
        client = GeminiClient(api_key="AIzaSecretDontLogMe", base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("INFO"):
            client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        messages = [r.message for r in caplog.records]
        assert any("calling" in m and "gemini-2.5-pro" in m for m in messages)
        assert any("REDACTED" in m for m in messages)
        assert not any("AIzaSecretDontLogMe" in m for m in messages)

    def test_a_failed_call_does_not_leak_the_api_key_either(self, monkeypatch, caplog):
        def fake_stream(method, url, *, json, timeout):
            return FakeStream(enter_exc=httpx.ReadTimeout("The read operation timed out"))

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
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
        never str(exc). Uses a real httpx.Response (not the FakeHttpResponse
        fake) so raise_for_status() produces the real, authentic message -
        a 401 arrives with its status/headers immediately in practice, so
        this models it succeeding through the streaming `with` block and
        failing on the production code's own `response.raise_for_status()`
        call afterward, same as the real flow."""
        real_key = "AIzaSecretDontLogMe"

        def fake_stream(method, url, *, json, timeout):
            request = httpx.Request("POST", url)
            response = httpx.Response(401, request=request, json={"error": "unauthorized"})
            return FakeStream(response)

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
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

    def test_a_slow_call_logs_heartbeats_without_leaking_the_key(self, monkeypatch, caplog):
        """Same gap as OpenAICompatibleClient's own version of this test -
        and since Gemini's key lives in the URL's query string, the
        heartbeat line must use the same redacted safe_url every other log
        line here already uses, not the raw `url` variable."""
        monkeypatch.setattr("shared.src.llm.gemini._HEARTBEAT_INTERVAL_SECONDS", 0.05)
        real_key = "AIzaSecretDontLogMe"

        def fake_stream(method, url, *, json, timeout):
            return FakeStream(FakeHttpResponse({"candidates": [{"content": {"parts": [
                {"functionCall": {"name": "submit_rca_finding", "args": {}}}
            ]}}]}), sleep_before_enter=0.2)

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
        client = GeminiClient(api_key=real_key, base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("INFO"):
            client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        messages = [r.message for r in caplog.records]
        heartbeats = [m for m in messages if "still waiting" in m]
        assert len(heartbeats) >= 2
        assert all("REDACTED" in m for m in heartbeats)
        assert not any(real_key in m for m in messages)

    def test_logs_time_to_first_byte_separately_and_never_leaks_the_key(self, monkeypatch, caplog):
        """Found 2026-10-17, same gap as OpenAICompatibleClient's own
        version of this test - must also pass through the redacted
        safe_url, same as every other log line here."""
        def fake_stream(method, url, *, json, timeout):
            return FakeStream(FakeHttpResponse({"candidates": [{"content": {"parts": [
                {"functionCall": {"name": "submit_rca_finding", "args": {}}}
            ]}}]}))

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
        client = GeminiClient(api_key="AIzaSecretDontLogMe", base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("INFO"):
            client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])

        messages = [r.message for r in caplog.records]
        assert any("sent response headers" in m and "REDACTED" in m for m in messages)
        assert any("fully responded" in m and "REDACTED" in m for m in messages)
        assert not any("AIzaSecretDontLogMe" in m for m in messages)

    def test_a_timeout_before_any_response_headers_never_logs_ttfb(self, monkeypatch, caplog):
        """The gateway never responding at all must not produce a "sent
        response headers" line - that absence is itself the diagnostic
        signal this feature exists to surface."""
        def fake_stream(method, url, *, json, timeout):
            return FakeStream(enter_exc=httpx.ReadTimeout("The read operation timed out"))

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
        client = GeminiClient(api_key="k", base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("INFO"):
            try:
                client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.ReadTimeout:
                pass

        messages = [r.message for r in caplog.records]
        assert not any("sent response headers" in m for m in messages)

    def test_an_immediate_4xx_logs_the_response_body(self, monkeypatch, caplog):
        """Same gap as OpenAICompatibleClient's own version of this test -
        found 2026-10-18 from a real production run where a deepseek call
        through this same adapter family failed fast with a bare 403 and
        no further information about why."""
        def fake_stream(method, url, *, json, timeout):
            request = httpx.Request("POST", url)
            response = httpx.Response(403, request=request, json={"error": "request blocked by policy"})
            return FakeStream(response)

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
        client = GeminiClient(api_key="k", base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.HTTPStatusError:
                pass

        messages = [r.message for r in caplog.records]
        assert any("request blocked by policy" in m for m in messages)

    def test_the_api_key_is_redacted_even_from_an_echoed_error_body(self, monkeypatch, caplog):
        """Defensive: unlike the URL (already redacted via safe_url), a
        proxy/WAF-generated error page could in principle echo the blocked
        request's full URL - including the key living in its query string
        - back in its own error body. The same redaction applied to every
        other log line here must also cover this one."""
        real_key = "AIzaSecretDontLogMe"

        def fake_stream(method, url, *, json, timeout):
            request = httpx.Request("POST", url)
            response = httpx.Response(403, request=request, json={"error": f"blocked url with key {real_key}"})
            return FakeStream(response)

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
        client = GeminiClient(api_key=real_key, base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.HTTPStatusError:
                pass

        messages = [r.message for r in caplog.records]
        assert any("blocked url with key" in m for m in messages)
        assert not any(real_key in m for m in messages)
        assert any("[REDACTED]" in m for m in messages)

    def test_a_trivially_short_api_key_does_not_mangle_unrelated_text(self, monkeypatch, caplog):
        """Mirrors OpenAICompatibleClient's own version of this test -
        gemini.py's _safe_exc_summary carries the identical short-secret-
        collision risk (a one-letter "secret" like the "k" placeholder
        this file's other tests use also matches the "k" inside
        "blocked"), so it needs the same regression coverage."""
        def fake_stream(method, url, *, json, timeout):
            request = httpx.Request("POST", url)
            response = httpx.Response(403, request=request, json={"error": "request blocked by policy"})
            return FakeStream(response)

        monkeypatch.setattr("shared.src.llm.gemini.httpx.stream", fake_stream)
        client = GeminiClient(api_key="k", base_url="https://generativelanguage.googleapis.com/v1beta")

        with caplog.at_level("WARNING"):
            try:
                client.messages.create(model="gemini-2.5-pro", max_tokens=10, thinking=None, system="s", tools=[_TOOL_SCHEMA], messages=[])
            except httpx.HTTPStatusError:
                pass

        messages = [r.message for r in caplog.records]
        assert any("request blocked by policy" in m for m in messages)
        assert not any("[REDACTED]" in m for m in messages)
