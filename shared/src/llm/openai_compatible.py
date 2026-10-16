"""Adapts the OpenAI chat-completions wire format to the narrow
`AnthropicClientLike` interface `pipeline/rca_agent.py` depends on.

Used as-is or in a documented compatible mode by OpenAI, Azure OpenAI,
DeepSeek, Qwen (DashScope), Grok (x.ai), Ollama, and LM Studio - one
adapter, parametrized by base URL and a couple of Azure-only fields,
instead of seven near-identical ones.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from shared.src.llm.base import NormalizedResponse, ToolUseBlock
from shared.src.llm.heartbeat import log_heartbeat

log = logging.getLogger(__name__)

# Module-level so a test can monkeypatch it down to something short-lived
# instead of waiting out a real 30s interval. Read fresh from the module
# namespace on every call (not a function-default), so monkeypatching it
# takes effect even though _create() already exists by the time a test runs.
_HEARTBEAT_INTERVAL_SECONDS = 30.0


def _safe_exc_summary(exc: BaseException) -> str:
    """A short, provably-secret-free description of an exception for a log
    line - just the exception class, plus an HTTP status code when one is
    actually available (`httpx.HTTPStatusError.response.status_code`).
    Deliberately never `str(exc)`: `httpx.HTTPStatusError`'s own string
    representation embeds the full request URL - for an Azure deployment
    the API key is a header, not the URL, so that specific leak path
    doesn't apply here, but staying off `str(exc)` entirely keeps this
    safe regardless of what any given provider's error body/message might
    ever embed."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status is not None:
        return f"{type(exc).__name__}(status={status})"
    return type(exc).__name__


_DEFAULT_AZURE_API_VERSION = "2024-08-01-preview"


class _MessagesNamespace:
    def __init__(self, client: "OpenAICompatibleClient"):
        self._client = client

    def create(self, **kwargs: Any) -> NormalizedResponse:
        return self._client._create(**kwargs)


class OpenAICompatibleClient:
    def __init__(
        self,
        *,
        api_key: str = "",
        base_url: str,
        is_azure: bool = False,
        api_version: str = "",
        deployment: str = "",
        supports_strict_tool_schema: bool = False,
        timeout: float = 600.0,
    ):
        if not base_url:
            raise ValueError("base_url is required for an OpenAI-compatible provider")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.is_azure = is_azure
        self.api_version = api_version or _DEFAULT_AZURE_API_VERSION
        self.deployment = deployment
        self.supports_strict_tool_schema = supports_strict_tool_schema
        # Found 2026-10-16 from a real production traceback: the old flat
        # `timeout: float = 60.0` applied the same 60s to every phase
        # (connect/write/pool *and* read), and it was the read phase that
        # actually failed - waiting for a custom enterprise LLM gateway
        # (DeepSeek via a Siemens-internal proxy) to even start streaming
        # back an 8000-max-token completion over a now much larger
        # evidence prompt (this week's new guest-log collectors added
        # several hundred more lines per machine). Split so a genuinely
        # dead endpoint still fails fast (connect) while a slow-to-respond
        # one gets real patience on the phase that actually failed (read).
        #
        # 240s still wasn't enough in the real deployment this was found
        # in - confirmed the request itself was never the problem: the
        # Portal "test connection" button (shared/src/llm/credential_test.py)
        # sends a trivial `max_tokens=1` one-word completion and gets a
        # fast reply, while the real RCA call asks for up to 8000 tokens
        # of output under a *forced* structured tool-call, over a much
        # larger evidence prompt - a fundamentally heavier request a slow
        # or custom gateway can legitimately take minutes to fully decode,
        # not seconds. Raised to match Anthropic's own SDK default (10
        # minutes) - the one path in this catalog already proven to need
        # exactly this much patience for the same kind of call, rather
        # than picking another number by guesswork.
        self.timeout = httpx.Timeout(connect=10.0, read=timeout, write=30.0, pool=10.0)
        self.messages = _MessagesNamespace(self)

    def _endpoint_and_headers(self, model: str) -> tuple[str, dict[str, str]]:
        if self.is_azure:
            url = (
                f"{self.base_url}/openai/deployments/{self.deployment or model}"
                f"/chat/completions?api-version={self.api_version}"
            )
            return url, {"api-key": self.api_key, "Content-Type": "application/json"}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return f"{self.base_url}/chat/completions", headers

    def _create(
        self,
        *,
        model: str,
        max_tokens: int,
        thinking: dict | None = None,  # Anthropic-only extended thinking - no
        # cross-provider equivalent exists, so it's dropped rather than guessed at.
        system: str,
        tools: list[dict],
        messages: list[dict],
    ) -> NormalizedResponse:
        tool_schema = tools[0]
        function: dict[str, Any] = {
            "name": tool_schema["name"],
            "description": tool_schema.get("description", ""),
            "parameters": tool_schema["input_schema"],
        }
        if self.supports_strict_tool_schema and tool_schema.get("strict"):
            function["strict"] = True

        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, *messages],
            "tools": [{"type": "function", "function": function}],
            # Forces exactly one call to this tool - the same "call this
            # exactly once" contract the Anthropic prompt states in words,
            # enforced structurally here instead.
            "tool_choice": {"type": "function", "function": {"name": tool_schema["name"]}},
        }

        url, headers = self._endpoint_and_headers(model)
        # Found 2026-10-16, tracing a real production timeout: this call
        # had no logging of its own - the only way to know it was even
        # the thing hanging was reading a raised exception's own
        # traceback. Logs the endpoint/model before sending (never
        # headers/api_key) and the outcome + duration whichever way the
        # call goes, so a slow-but-eventually-successful call and a
        # genuinely-timed-out one are both visible without needing to
        # wait for an exception to bubble all the way up to routes_runs.py.
        log.info("OpenAICompatibleClient: calling %s (model=%s, max_tokens=%s)", url, model, max_tokens)
        started = time.monotonic()
        # Found 2026-10-17 from a real production run: a slow/custom
        # gateway can sit silent on this call for the *entire* several-
        # minute read timeout, and until now nothing logged anything in
        # that window - indistinguishable from the app itself hanging.
        # Logs "still waiting" on a fixed interval for as long as this one
        # call is actually in flight; does not change the call itself.
        heartbeat_label = f"OpenAICompatibleClient: call to {url} (model={model})"
        # Found 2026-10-17: a plain httpx.post() gives no way to tell
        # "the gateway never responded at all" apart from "the gateway
        # sent a response and started on the body, then stalled" - both
        # looked identical (just a ReadTimeout after the full window).
        # httpx.stream() returns as soon as the response headers arrive,
        # before the body is read, so logging in between those two steps
        # gives a genuine time-to-first-byte marker.
        try:
            with log_heartbeat(log, heartbeat_label, interval=_HEARTBEAT_INTERVAL_SECONDS):
                with httpx.stream("POST", url, headers=headers, json=payload, timeout=self.timeout) as response:
                    log.info(
                        "OpenAICompatibleClient: %s sent response headers (status=%s) after %.1fs - reading body",
                        url, response.status_code, time.monotonic() - started,
                    )
                    response.read()
            response.raise_for_status()
        except Exception as exc:
            log.warning(
                "OpenAICompatibleClient: call to %s failed after %.1fs (%s)",
                url, time.monotonic() - started, _safe_exc_summary(exc),
            )
            raise
        log.info("OpenAICompatibleClient: %s fully responded (%s) after %.1fs", url, response.status_code, time.monotonic() - started)
        data = response.json()

        choice = data["choices"][0]
        tool_calls = (choice.get("message") or {}).get("tool_calls") or []
        if not tool_calls:
            return NormalizedResponse(content=[], stop_reason=choice.get("finish_reason", "stop"))

        call = tool_calls[0]["function"]
        arguments = call["arguments"]
        # Handed through as whatever the API actually returned (almost
        # always a JSON string per the OpenAI spec) - rca_agent.py already
        # defensively `json.loads()`s a string `.input`, so this reuses
        # that existing parsing path rather than duplicating it here.
        return NormalizedResponse(content=[ToolUseBlock(name=call["name"], input=arguments)])
