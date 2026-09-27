"""Adapts the OpenAI chat-completions wire format to the narrow
`AnthropicClientLike` interface `pipeline/rca_agent.py` depends on.

Used as-is or in a documented compatible mode by OpenAI, Azure OpenAI,
DeepSeek, Qwen (DashScope), Grok (x.ai), Ollama, and LM Studio - one
adapter, parametrized by base URL and a couple of Azure-only fields,
instead of seven near-identical ones.
"""
from __future__ import annotations

from typing import Any

import httpx

from shared.src.llm.base import NormalizedResponse, ToolUseBlock

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
        timeout: float = 60.0,
    ):
        if not base_url:
            raise ValueError("base_url is required for an OpenAI-compatible provider")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.is_azure = is_azure
        self.api_version = api_version or _DEFAULT_AZURE_API_VERSION
        self.deployment = deployment
        self.supports_strict_tool_schema = supports_strict_tool_schema
        self.timeout = timeout
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
        response = httpx.post(url, headers=headers, json=payload, timeout=self.timeout)
        response.raise_for_status()
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
