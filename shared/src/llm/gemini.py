"""Adapts Google's generateContent wire format to the narrow
`AnthropicClientLike` interface `pipeline/rca_agent.py` depends on.

Gemini's function-declaration schema is a strict subset of OpenAPI 3.0,
not full JSON Schema - fields Culprit's tool schema uses that Gemini's
dialect doesn't recognize (`additionalProperties`) are stripped rather
than sent and rejected with a 400. Forcing the tool call uses Gemini's
own mechanism (`tool_config.function_calling_config.mode = "ANY"`
restricted to this one function name), the same "call this exactly
once" contract the other adapters enforce structurally.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from shared.src.llm.base import NormalizedResponse, ToolUseBlock
from shared.src.llm.heartbeat import log_heartbeat

log = logging.getLogger(__name__)

# Same reasoning as shared/src/llm/openai_compatible.py's own copy of this
# constant - module-level so a test can monkeypatch it short rather than
# waiting out a real 30s interval.
_HEARTBEAT_INTERVAL_SECONDS = 30.0


_MAX_LOGGED_BODY_CHARS = 500


def _safe_exc_summary(exc: BaseException, *, secret: str = "") -> str:
    """A short, provably-secret-free description of an exception for a log
    line - the exception class, an HTTP status code when one is actually
    available, and (found 2026-10-18, a real immediate 4xx with otherwise
    zero information about *why*) a truncated copy of the response body
    when there is one - the provider's own error message, the one piece
    of information that actually explains an immediate failure. Deliberately
    never `str(exc)`: `httpx.HTTPStatusError`'s own string representation
    embeds the full request URL, which for this client carries the real
    API key in its query string - str(exc) would re-leak exactly the
    secret this module's own logging redacts via safe_url, just through
    the exception message instead of a log argument. The body text itself
    comes from the server, not the request, so it isn't the same leak path
    - but `secret` (the real api_key, when the caller has one) is still
    scrubbed out of it defensively, in case some proxy/WAF-generated error
    page echoes back the request URL it blocked."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status is None:
        return type(exc).__name__
    summary = f"{type(exc).__name__}(status={status})"
    body = getattr(exc.response, "text", None)
    if body:
        # A short "secret" (e.g. a test's throwaway placeholder, or in
        # principle a very short real token) risks matching ordinary
        # substrings of the message itself (a one-character "secret" like
        # "k" also matches the "k" in "blocked") and mangling it instead of
        # protecting anything real - so only redact when it's long enough
        # to plausibly be a genuine credential rather than common text.
        if secret and len(secret) >= 8:
            body = body.replace(secret, "[REDACTED]")
        summary += f": {body[:_MAX_LOGGED_BODY_CHARS]}"
    return summary


class _MessagesNamespace:
    def __init__(self, client: "GeminiClient"):
        self._client = client

    def create(self, **kwargs: Any) -> NormalizedResponse:
        return self._client._create(**kwargs)


def _strip_unsupported_schema_keys(schema: Any) -> Any:
    """Recursively drops JSON Schema keywords Gemini's function-declaration
    dialect doesn't accept (`additionalProperties` is the one Culprit's own
    tool schema actually uses; this stays defensive about the shape rather
    than hardcoding assumptions about what else might show up)."""
    if isinstance(schema, dict):
        return {
            key: _strip_unsupported_schema_keys(value)
            for key, value in schema.items()
            if key != "additionalProperties"
        }
    if isinstance(schema, list):
        return [_strip_unsupported_schema_keys(item) for item in schema]
    return schema


class GeminiClient:
    def __init__(self, *, api_key: str, base_url: str, timeout: float = 600.0):
        if not api_key:
            raise ValueError("api_key is required for Gemini")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        # Same fix, same reasoning as shared/src/llm/openai_compatible.py::
        # OpenAICompatibleClient (found 2026-10-16, a real production
        # timeout, raised twice: first the type - flat vs. split by phase -
        # then the value, once 240s on the read phase still wasn't enough
        # for a real large tool-calling completion through a slow/custom
        # gateway). Matches Anthropic's own 10-minute SDK default rather
        # than picking another number by guesswork. Gemini is an
        # independently-activatable catalog provider just like the
        # openai_compatible family, so it needs the identical treatment.
        self.timeout = httpx.Timeout(connect=10.0, read=timeout, write=30.0, pool=10.0)
        self.messages = _MessagesNamespace(self)

    def _create(
        self,
        *,
        model: str,
        max_tokens: int,
        thinking: dict | None = None,  # no cross-provider equivalent - dropped, not guessed at
        system: str,
        tools: list[dict],
        messages: list[dict],
    ) -> NormalizedResponse:
        tool_schema = tools[0]
        user_text = "\n\n".join(m["content"] for m in messages if m.get("role") == "user")

        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user_text}]}],
            "tools": [{
                "functionDeclarations": [{
                    "name": tool_schema["name"],
                    "description": tool_schema.get("description", ""),
                    "parameters": _strip_unsupported_schema_keys(tool_schema["input_schema"]),
                }],
            }],
            "tool_config": {
                "function_calling_config": {
                    "mode": "ANY",
                    "allowed_function_names": [tool_schema["name"]],
                },
            },
            "generationConfig": {"maxOutputTokens": max_tokens},
        }

        url = f"{self.base_url}/models/{model}:generateContent?key={self.api_key}"
        # Found 2026-10-16, same tracing added to
        # shared/src/llm/openai_compatible.py's own _create() - logs the
        # outcome + duration whichever way the call goes. Unlike that
        # adapter, Gemini's API key lives in the URL's own query string
        # (not a header), so the logged endpoint must have it redacted -
        # logging `url` as-is here would leak the credential into logs.
        safe_url = f"{self.base_url}/models/{model}:generateContent?key=REDACTED"
        log.info("GeminiClient: calling %s (max_tokens=%s)", safe_url, max_tokens)
        started = time.monotonic()
        # Found 2026-10-17, same gap as OpenAICompatibleClient's own fix:
        # a slow/custom gateway can sit silent for the entire multi-minute
        # read timeout with nothing logged in that window. Logs "still
        # waiting" on a fixed interval while this one call is in flight -
        # uses safe_url, same as every other log line here, so the API key
        # never ends up in a heartbeat line either.
        heartbeat_label = f"GeminiClient: call to {safe_url} (model={model})"
        # Found 2026-10-17, same gap and same fix as
        # OpenAICompatibleClient's own _create(): httpx.stream() returns
        # as soon as response headers arrive, before the body is read, so
        # logging in between gives a genuine time-to-first-byte marker -
        # "the gateway never responded at all" vs. "it responded and then
        # stalled partway through the body" used to look identical.
        try:
            with log_heartbeat(log, heartbeat_label, interval=_HEARTBEAT_INTERVAL_SECONDS):
                with httpx.stream("POST", url, json=payload, timeout=self.timeout) as response:
                    log.info(
                        "GeminiClient: %s sent response headers (status=%s) after %.1fs - reading body",
                        safe_url, response.status_code, time.monotonic() - started,
                    )
                    response.read()
            response.raise_for_status()
        except Exception as exc:
            log.warning(
                "GeminiClient: call to %s failed after %.1fs (%s)",
                safe_url, time.monotonic() - started, _safe_exc_summary(exc, secret=self.api_key),
            )
            raise
        log.info("GeminiClient: %s fully responded (%s) after %.1fs", safe_url, response.status_code, time.monotonic() - started)
        data = response.json()

        candidates = data.get("candidates") or []
        parts = (candidates[0].get("content") or {}).get("parts", []) if candidates else []
        call = next((p["functionCall"] for p in parts if "functionCall" in p), None)
        if call is None:
            finish_reason = candidates[0].get("finishReason", "stop") if candidates else "stop"
            return NormalizedResponse(content=[], stop_reason=finish_reason)

        # Gemini hands back `args` already parsed (a dict), unlike the
        # OpenAI-compatible adapters' JSON-string `arguments` - rca_agent.py
        # accepts either (it only `json.loads()`s when `.input` is a str).
        return NormalizedResponse(content=[ToolUseBlock(name=call["name"], input=call.get("args", {}))])
