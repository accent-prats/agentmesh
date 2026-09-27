"""Every AI provider the Portal's admin-only AI Providers screen
(`portal/api/routers/ai_providers.py`) can configure, and what
`factory.build_client` needs to know to build a working client for each
one - shared across every app that needs an LLM call, not just Culprit's
deep RCA agent, which is the one consumer that exists today.

Restricted to providers that can actually do tool-calling - a
chat/completion call with a forced tool call, structured schema-shaped
input. This is also why DeepL isn't here: it's a translation API, not a
chat model, and has no tool-calling concept at all - "AI provider" in the
catalog the platform's `test` branch has, but "can this actually run an
agent that needs to call a tool" here.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderSpec:
    label: str
    kind: str  # "anthropic" | "openai_compatible" | "gemini"
    default_model: str
    default_base_url: str = ""
    requires_api_key: bool = True
    is_azure: bool = False
    # A curated, known-current set of model ids for this provider - what
    # the admin screen's Model dropdown offers. Deliberately not
    # exhaustive or fetched live (a wrong/renamed id here just means an
    # admin picks "Other" and types the real one; it never blocks saving
    # or calling whatever model id ends up in that field). Empty for
    # providers where no fixed list makes sense (LM Studio: whatever the
    # admin happens to have loaded locally).
    model_options: tuple[str, ...] = ()
    # Whether this provider's OpenAI-compatible surface has been verified
    # (by its own docs) to honor `strict: true` structured-output tool
    # schemas. Providers with this off still get the *same* forced
    # tool_choice and the *same* Pydantic/evidence-ref validation
    # afterwards (see rca_agent.py) - they just don't get the extra
    # belt-and-suspenders the strict flag buys on top of that.
    supports_strict_tool_schema: bool = False

    @property
    def requires_base_url(self) -> bool:
        """False only for Anthropic, the one provider with no endpoint
        concept at all in its own SDK. Every other provider needs one -
        for most of them `default_base_url` already supplies it, but
        Azure OpenAI's resource endpoint has no sane default, so this is
        what api/deps.py::get_rca_agent() checks before treating a
        provider as "configured", not just `default_base_url` being set."""
        return self.kind != "anthropic"


PROVIDER_CATALOG: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        label="Anthropic", kind="anthropic", default_model="claude-opus-5",
        supports_strict_tool_schema=True,
        model_options=("claude-opus-5", "claude-sonnet-5", "claude-fable-5-1", "claude-haiku-4-5-20251001"),
    ),
    "openai": ProviderSpec(
        label="OpenAI", kind="openai_compatible", default_model="gpt-5",
        default_base_url="https://api.openai.com/v1",
        supports_strict_tool_schema=True,
        model_options=("gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-4o", "gpt-4o-mini"),
    ),
    "azure_openai": ProviderSpec(
        label="Azure OpenAI", kind="openai_compatible", default_model="gpt-5",
        default_base_url="",  # the resource endpoint, e.g. https://<resource>.openai.azure.com - has no sane default
        is_azure=True,
        supports_strict_tool_schema=True,
        # Same underlying models as OpenAI - what actually routes the call
        # is the deployment name below, not this field, but Azure resource
        # deployments are conventionally named after (or set to) one of these.
        model_options=("gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-4o", "gpt-4o-mini"),
    ),
    "gemini": ProviderSpec(
        label="Google Gemini", kind="gemini", default_model="gemini-2.5-pro",
        default_base_url="https://generativelanguage.googleapis.com/v1beta",
        model_options=("gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"),
    ),
    "grok": ProviderSpec(
        label="xAI Grok", kind="openai_compatible", default_model="grok-4",
        default_base_url="https://api.x.ai/v1",
        supports_strict_tool_schema=True,
        model_options=("grok-4", "grok-4-fast", "grok-3"),
    ),
    "qwen": ProviderSpec(
        label="Alibaba Qwen", kind="openai_compatible", default_model="qwen-max",
        default_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        model_options=("qwen-max", "qwen-plus", "qwen-turbo"),
    ),
    "deepseek": ProviderSpec(
        label="DeepSeek", kind="openai_compatible", default_model="deepseek-chat",
        default_base_url="https://api.deepseek.com/v1",
        model_options=("deepseek-chat", "deepseek-reasoner"),
    ),
    "ollama": ProviderSpec(
        label="Ollama (local)", kind="openai_compatible", default_model="llama3.1",
        default_base_url="http://localhost:11434/v1", requires_api_key=False,
        model_options=("llama3.1", "llama3.2", "mistral", "qwen2.5"),
    ),
    "lmstudio": ProviderSpec(
        label="LM Studio (local)", kind="openai_compatible", default_model="",
        default_base_url="http://localhost:1234/v1", requires_api_key=False,
        # No curated list makes sense here - it's whatever the admin
        # happens to have loaded locally, a free-text field always.
    ),
}
