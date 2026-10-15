# shared — Common Library

Code shared across the platform's backend services. Import directly — this is not a
packaged library, it lives in the monorepo and is resolved via `PYTHONPATH`.

---

## Contents

```
shared/src/
├── feature_flags/
│   ├── __init__.py
│   ├── client.py         # GrowthBookClient — wraps the GrowthBook Python SDK
│   ├── dependencies.py   # get_feature_flags() FastAPI dependency
│   └── middleware.py     # FlagMiddleware — builds per-request user attributes
│
└── llm/                  # Multi-provider AI client construction (added 2026-09-27)
    ├── __init__.py
    ├── catalog.py           # PROVIDER_CATALOG — every provider, its wire format,
    │                        # default endpoint/model, and curated model list
    ├── base.py              # ToolUseBlock / NormalizedResponse — the narrow,
    │                        # Anthropic-shaped response every adapter normalizes into
    ├── openai_compatible.py # OpenAI, Azure OpenAI, DeepSeek, Qwen, Grok, Ollama, LM Studio
    ├── gemini.py            # Google Gemini's own wire format
    ├── factory.py           # build_client(provider, ...) → whichever adapter matches
    └── credential_test.py   # The "Test connection" button's real (per-provider-kind) live call
```

---

## Feature Flags (`shared/src/feature_flags/`)

Used today by Portal. See [docs/feature-flags/README.md](../docs/feature-flags/README.md) for
the full setup and usage guide — this section is just the import surface.

```python
from shared.src.feature_flags import FlagMiddleware, GrowthBookClient, set_client, get_feature_flags
```

- `GrowthBookClient` / `set_client` / `get_client` — initialized once at app startup (see
  `portal/api/main.py`'s lifespan handler), polls GrowthBook for flag definitions in the background.
- `FlagMiddleware` — added to the FastAPI app, builds the per-request user attribute dict
  (from the JWT) that GrowthBook targeting rules match against. It also enforces one flag
  itself, directly in `dispatch()`: when `shared.maintenance.readonly-mode` is on, every write
  request (`POST`/`PUT`/`PATCH`/`DELETE`) other than auth/health is rejected with `503` before
  it reaches a route. See [docs/feature-flags/README.md](../docs/feature-flags/README.md) for
  this and the rest of the flag list.
- `get_feature_flags` — a FastAPI dependency any router can use to read `request.state.flags`.

---

## Multi-provider AI (`shared/src/llm/`)

Used today by Culprit's deep RCA agent; written to be app-agnostic so a future app gets the same
provider catalog for free. Configuration (which provider, its credentials) is a platform-wide,
admin-managed concern owned by Portal (`portal/api/routers/ai_providers.py`,
[portal/README.md#ai-providers](../portal/README.md#ai-providers)) — this package is only about
*building a working client* from that configuration, so the real model call goes straight from
the consuming app to the provider instead of proxying through Portal.

```python
from shared.src.llm import PROVIDER_CATALOG, build_client

client = build_client("openai", api_key="sk-...", base_url="https://api.openai.com/v1")
response = client.messages.create(model="gpt-5", max_tokens=..., system=..., tools=[...], messages=[...])
```

- `PROVIDER_CATALOG` — every supported provider (`ProviderSpec`: label, wire-format `kind`,
  default endpoint/model, whether it needs an API key or an endpoint, a curated `model_options`
  list for the admin UI's dropdown). Adding a provider is one new entry here; every consuming app
  picks it up without a code change on its side.
- `build_client(provider, *, api_key, base_url, api_version="", deployment="")` — returns
  whichever adapter matches, all speaking the *same* narrow, deliberately Anthropic-shaped
  interface (`client.messages.create(...) -> response` where `response.content` is a list of
  blocks and a `tool_use` block has `.type`/`.name`/`.input`) — so a caller written against the
  real Anthropic SDK (Culprit's `pipeline/rca_agent.py::DeepRCAAgent`) never needs to know which
  provider actually ran.
- Two wire formats cover the whole catalog: `openai_compatible.py` (OpenAI, Azure OpenAI,
  DeepSeek, Qwen, Grok, Ollama, LM Studio all speak the OpenAI chat-completions shape, as-is or in
  a documented compatible mode) and `gemini.py` (Google's own format). Anthropic itself needs no
  adapter — `build_client("anthropic", ...)` returns the real `anthropic.Anthropic()` client.
- **DeepL is deliberately not in the catalog** — it's a translation API with no tool-calling
  concept at all, so there's no applicable adapter for it, only an absence of one.
- `credential_test.py::test_ai_provider_credentials` — the real (not mocked) live call behind the
  admin UI's "Test connection" button: a cheap model-catalog fetch for Anthropic/Gemini, a
  one-token completion for the OpenAI-compatible family.

**Verification note:** Anthropic is verified end-to-end against a real account; the other eight
providers are verified against each one's *documented* wire format via a fake HTTP transport
(`shared/tests/test_llm_adapters.py`, `test_credential_test.py`), not live credentials. Test a
provider for real via the admin screen's "Test connection" button before relying on it.

---

## Import paths

For local development outside Docker, either set `PYTHONPATH` manually or run from the repo root:

```bash
PYTHONPATH=. python -m uvicorn portal.api.main:app --reload
```
