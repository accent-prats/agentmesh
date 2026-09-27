"""Multi-provider LLM client construction - shared across every app on the
platform, not owned by any one of them.

Configuration (which provider is active, its credentials, its model) is
an admin-managed, platform-level concern owned by the Portal (see
`portal/api/routers/ai_providers.py` and `portal/db.py::AIProviderSetting`)
- deliberately not duplicated per app, so a second app added later gets
the same admin screen and the same providers for free instead of
re-implementing this. Building an actual client from that configuration,
however, happens locally in whichever app is about to call it (Culprit's
`api/deps.py::get_rca_agent()` today) - that's what this package is for,
so the real model call goes straight from that app to the provider
instead of proxying every request through the Portal.

Every adapter here speaks the same narrow, deliberately Anthropic-shaped
interface (`client.messages.create(model=, max_tokens=, thinking=,
system=, tools=, messages=) -> response` where `response.content` is a
list of blocks and a `tool_use` block has `.type`/`.name`/`.input`) so a
caller written against the real Anthropic SDK (like Culprit's
`pipeline/rca_agent.py::DeepRCAAgent`) never needs to know which provider
actually ran.

Anthropic itself needs no adapter - `factory.build_client("anthropic", ...)`
returns the real `anthropic.Anthropic()` client directly. Every other
provider in `catalog.PROVIDER_CATALOG` falls into one of two wire formats:

  - `openai_compatible.OpenAICompatibleClient` - the OpenAI chat-completions
    request/response shape, used as-is or in a documented compatible mode
    by OpenAI, Azure OpenAI, DeepSeek, Qwen (DashScope), Grok (x.ai),
    Ollama, and LM Studio.
  - `gemini.GeminiClient` - Google's own generateContent format.

Deliberately excluded from the catalog: DeepL. It's a translation API with
no chat/tool-calling capability at all - it cannot run `submit_rca_finding`
or anything like it, so there is no applicable adapter for it, only an
absence of one.

Verification note: unlike Anthropic (verified end-to-end against a real
account) and unlike mem0 (also verified live), these adapters are
verified against each provider's *documented* wire format via
`shared/tests/test_llm_adapters.py`'s fake HTTP transport, not against
live credentials for each of the eight of them. If you intend to actually
run one of these in anger, test it against a real key first via the
Portal admin AI Providers screen's "Test connection" button.
"""
from __future__ import annotations

from shared.src.llm.catalog import PROVIDER_CATALOG
from shared.src.llm.factory import build_client

__all__ = ["PROVIDER_CATALOG", "build_client"]
