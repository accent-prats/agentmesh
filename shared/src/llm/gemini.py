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

from typing import Any

import httpx

from shared.src.llm.base import NormalizedResponse, ToolUseBlock


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
    def __init__(self, *, api_key: str, base_url: str, timeout: float = 60.0):
        if not api_key:
            raise ValueError("api_key is required for Gemini")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
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
        response = httpx.post(url, json=payload, timeout=self.timeout)
        response.raise_for_status()
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
