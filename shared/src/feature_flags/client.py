"""
GrowthBook SDK client — singleton wrapper around the growthbook Python SDK.

Fetches feature definitions from the GrowthBook API on startup and refreshes
them in the background every `refresh_interval` seconds.  All flag evaluation
happens in-memory (no per-request network calls), so there is zero latency
overhead on each request.

Falls back gracefully when GrowthBook is unreachable: every flag returns its
configured default value, so the application keeps running normally.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from growthbook import GrowthBook

log = logging.getLogger(__name__)

# httpx logs every outbound request at INFO level by default.
# GrowthBook polls every ~60 s, which creates constant INFO noise.
# Raise the threshold to WARNING so only actual errors surface.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# Module-level singleton — set once during app startup via set_client()
_client: GrowthBookClient | None = None


class GrowthBookClient:
    """Manages feature-flag state for one application process.

    Usage (in FastAPI lifespan):
        client = GrowthBookClient(api_host=..., client_key=...)
        await client.initialize()
        set_client(client)
        yield
        await client.shutdown()
    """

    def __init__(
        self,
        api_host: str,
        client_key: str,
        refresh_interval: int = 60,
    ) -> None:
        self._api_host = api_host.rstrip("/")
        self._client_key = client_key
        self._refresh_interval = refresh_interval
        self._features: dict[str, Any] = {}
        self._refresh_task: asyncio.Task | None = None

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Fetch features once, then start the background refresh loop."""
        await self._fetch_features()
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        log.info(
            "growthbook_initialized",
            extra={"feature_count": len(self._features), "api_host": self._api_host},
        )

    async def shutdown(self) -> None:
        """Cancel the background refresh task on app shutdown."""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

    # ── Evaluation ───────────────────────────────────────────────────────────

    def evaluate(self, attributes: dict[str, Any]) -> GrowthBook:
        """Return a GrowthBook evaluator bound to the given user attributes.

        The returned instance is lightweight (no I/O) and safe to create per
        request.  It holds a snapshot of the current feature definitions so
        flag changes propagate on the next refresh cycle.
        """
        return GrowthBook(
            attributes=attributes,
            features=self._features,
        )

    # ── Internal ─────────────────────────────────────────────────────────────

    async def _fetch_features(self) -> None:
        if not self._client_key or self._client_key == "sdk-":
            log.warning("growthbook_client_key_not_set — flags will use defaults")
            return
        try:
            async with httpx.AsyncClient(timeout=5.0) as http:
                resp = await http.get(
                    f"{self._api_host}/api/features/{self._client_key}"
                )
                resp.raise_for_status()
                data = resp.json()
                self._features = data.get("features", {})
                log.debug(
                    "growthbook_features_refreshed",
                    extra={"count": len(self._features)},
                )
        except Exception as exc:
            # Non-fatal: flags fall back to their configured defaults
            log.warning("growthbook_fetch_failed", extra={"error": str(exc)})

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self._refresh_interval)
            await self._fetch_features()


# ── Module-level accessors ────────────────────────────────────────────────────

def set_client(client: GrowthBookClient) -> None:
    """Register the singleton client.  Called once during app startup."""
    global _client
    _client = client


def get_client() -> GrowthBookClient:
    """Return the singleton client.  Raises if not yet initialized."""
    if _client is None:
        raise RuntimeError(
            "GrowthBook client not initialized. "
            "Call set_client() in your app's lifespan hook."
        )
    return _client
