"""Builds a client for whichever AI provider is configured, matching the
narrow `AnthropicClientLike` interface Culprit's `pipeline/rca_agent.py`
depends on.

The one place that knows the full provider catalog and which adapter
class backs each one - Culprit's `api/deps.py::get_rca_agent()` calls this
with whatever it fetched from the Portal's resolved-active-provider
endpoint, and never needs to know the adapters exist.
"""
from __future__ import annotations

from shared.src.llm.catalog import PROVIDER_CATALOG


class UnknownProvider(ValueError):
    pass


def build_client(
    provider: str,
    *,
    api_key: str = "",
    base_url: str = "",
    api_version: str = "",
    deployment: str = "",
):
    spec = PROVIDER_CATALOG.get(provider)
    if spec is None:
        raise UnknownProvider(f"Unknown AI provider: {provider!r}")

    if spec.kind == "anthropic":
        import anthropic

        return anthropic.Anthropic(api_key=api_key or None)

    if spec.kind == "gemini":
        from shared.src.llm.gemini import GeminiClient

        return GeminiClient(api_key=api_key, base_url=base_url or spec.default_base_url)

    if spec.kind == "openai_compatible":
        from shared.src.llm.openai_compatible import OpenAICompatibleClient

        return OpenAICompatibleClient(
            api_key=api_key,
            base_url=base_url or spec.default_base_url,
            is_azure=spec.is_azure,
            api_version=api_version,
            deployment=deployment,
            supports_strict_tool_schema=spec.supports_strict_tool_schema,
        )

    raise UnknownProvider(f"Provider {provider!r} has an unrecognized kind: {spec.kind!r}")
