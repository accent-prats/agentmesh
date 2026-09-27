"""A minimal live connection test per AI provider kind - not a stub.
Used by the Portal admin AI Providers screen's "Test connection" button
(`portal/api/routers/ai_providers.py`), same real-call-not-mock rule
Culprit's own `security/credential_test.py` applies to Azure/Datadog.
"""
from __future__ import annotations

import httpx

from shared.src.llm.catalog import PROVIDER_CATALOG


def test_ai_provider_credentials(provider: str, *, api_key: str, base_url: str, model: str, api_version: str = "", deployment: str = "") -> tuple[bool, str]:
    """A cheap model-catalog fetch for Anthropic and Gemini (no generation
    cost), a one-token completion for the OpenAI-compatible family (its
    documented model-listing endpoint isn't consistent enough across all
    seven of them to trust as a stand-in for "can this actually complete a
    request")."""
    spec = PROVIDER_CATALOG.get(provider)
    if spec is None:
        return False, f"Unknown AI provider: {provider!r}"
    if spec.requires_api_key and not api_key:
        return False, "No API key provided"
    resolved_base_url = (base_url or spec.default_base_url).rstrip("/")
    if not resolved_base_url and spec.requires_base_url:
        return False, "No endpoint configured for this provider"

    try:
        if spec.kind == "anthropic":
            import anthropic

            client = anthropic.Anthropic(api_key=api_key or None)
            models = client.models.list(limit=1)
            first = next(iter(models.data), None)
            return True, f"Authenticated (model catalog reachable{f', e.g. {first.id}' if first else ''})"

        if spec.kind == "gemini":
            response = httpx.get(f"{resolved_base_url}/models", params={"key": api_key}, timeout=15)
            response.raise_for_status()
            count = len(response.json().get("models", []))
            return True, f"Authenticated ({count} model(s) visible)"

        if spec.kind == "openai_compatible":
            if spec.is_azure:
                url = (
                    f"{resolved_base_url}/openai/deployments/{deployment or model}"
                    f"/chat/completions?api-version={api_version or '2024-08-01-preview'}"
                )
                headers = {"api-key": api_key, "Content-Type": "application/json"}
            else:
                url = f"{resolved_base_url}/chat/completions"
                headers = {"Content-Type": "application/json"}
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
            payload = {"model": model or spec.default_model, "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}
            response = httpx.post(url, headers=headers, json=payload, timeout=15)
            response.raise_for_status()
            return True, "Authenticated and completed a test request"

        return False, f"No connection test implemented for provider kind {spec.kind!r}"
    except httpx.HTTPStatusError as exc:
        return False, f"HTTP {exc.response.status_code}: {exc.response.text[:300]}"
    except Exception as exc:  # noqa: BLE001 - reporting the real error is the point of a test-connection button
        return False, str(exc)[:500]
