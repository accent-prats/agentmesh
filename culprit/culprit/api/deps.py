"""FastAPI dependencies - one shared session factory and lazily-built
demo pipeline components, so routes don't each re-derive them."""
from __future__ import annotations

from functools import lru_cache

from culprit.config import settings
from culprit.db.engine import make_engine, make_session_factory


@lru_cache
def get_session_factory():
    engine = make_engine(settings.database_url)
    return make_session_factory(engine)


@lru_cache
def get_retrieval_store():
    from culprit.retrieval.corpus import default_retrieval_store

    vendor_store = default_retrieval_store()
    if not settings.memory_enabled:
        return vendor_store
    try:
        from culprit.memory.store import get_store
        from culprit.retrieval.hybrid import HybridRetrievalStore

        return HybridRetrievalStore(vendor_store=vendor_store, memory_store=get_store())
    except ImportError:
        # CULPRIT_MEMORY_ENABLED=true but the optional `culprit[memory]`
        # extra (mem0ai + sentence-transformers) isn't installed - same
        # graceful-degradation shape as get_rca_agent() falling back to
        # the scripted agent when ANTHROPIC_API_KEY is unset. Logged once,
        # not raised: a missing optional extra must not take down the app.
        import logging

        logging.getLogger("culprit.api.deps").warning(
            "CULPRIT_MEMORY_ENABLED is true but mem0 isn't installed - "
            "install with pip install 'culprit[memory]'. Falling back to "
            "the vendor-doc-only retrieval store."
        )
        return vendor_store


def get_rca_agent():
    """Picks whichever AI provider the Portal admin's platform-wide AI
    Providers screen has marked active (portal/api/routers/ai_providers.py) -
    a call to Portal's own service-to-service endpoint, not a local DB read;
    this table is deliberately owned by the Portal, not Culprit, since it's
    shared by every app that needs an LLM call, not just this one. There is
    no default provider here: if no admin has ever picked one, or Portal
    isn't reachable at all (e.g. Culprit running standalone), this falls
    back to the original env-var-only behavior
    (ANTHROPIC_API_KEY/CULPRIT_RCA_MODEL) so a deployment that predates this
    feature - or never touches it - behaves exactly as before. Only falls
    through to the scripted demo agent when neither path has anything
    usable.

    Deliberately **not** `@lru_cache`d, unlike get_session_factory() and
    get_retrieval_store() - the config this reads now lives in a different
    process (Portal's DB, not Culprit's own), so an admin flipping the
    active provider must take effect on Culprit's next run without a
    restart, the same "not cached" reasoning build_live_collectors()
    already documents for Azure/Datadog. Called once per Pipeline
    construction (one network round-trip per run, not per machine), so
    the cost of not caching it is negligible next to the model call itself."""
    import os

    resolved = _fetch_active_ai_provider_from_portal()
    if resolved is not None:
        from shared.src.llm.catalog import PROVIDER_CATALOG
        from shared.src.llm.factory import build_client
        from culprit.pipeline.rca_agent import DeepRCAAgent

        spec = PROVIDER_CATALOG.get(resolved["provider"])
        if spec is not None:
            client = build_client(
                resolved["provider"],
                api_key=resolved["api_key"],
                base_url=resolved["base_url"],
                api_version=resolved["api_version"],
                deployment=resolved["deployment"],
            )
            return DeepRCAAgent(client=client, model=resolved["model"] or spec.default_model)

    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        from culprit.pipeline.rca_agent import DeepRCAAgent

        return DeepRCAAgent(model=settings.rca_model)
    from culprit.demo.scripted_rca import ScriptedRCAAgent

    return ScriptedRCAAgent()


def _fetch_active_ai_provider_from_portal() -> dict | None:
    """Returns the resolved active-provider dict from the Portal, or None
    if nothing usable came back - no admin has picked a provider yet, no
    `CULPRIT_PORTAL_JWT_SECRET` is configured (standalone Culprit, no
    Portal at all), or the Portal is unreachable. Every failure mode here
    is deliberately non-fatal: this is one optional integration among
    several (Azure, Datadog, mem0), never a hard dependency for a request
    that has nothing to do with the Portal."""
    if not settings.portal_jwt_secret:
        return None
    try:
        from datetime import datetime, timedelta, timezone

        import httpx
        from jose import jwt

        # Mints its own short-lived service token per portal/security.py's
        # create_service_token() shape (Culprit has no reason to import
        # Portal's module directly - it's a separate deployable - so this
        # just needs to encode the same claims with the same shared
        # secret; Portal's require_service dependency is what decodes it).
        token = jwt.encode(
            {"sub": "culprit", "type": "service", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
            settings.portal_jwt_secret, algorithm="HS256",
        )
        response = httpx.get(
            f"{settings.portal_internal_url}/api/ai-providers/resolved-active",
            headers={"Authorization": f"Bearer {token}"}, timeout=5,
        )
        response.raise_for_status()
        data = response.json()
        if not data.get("provider"):
            return None
        return data
    except Exception:  # noqa: BLE001 - see docstring; any failure here just means "use the env-var fallback"
        import logging

        logging.getLogger("culprit.api.deps").warning(
            "Could not fetch the active AI provider from the Portal - falling back to "
            "ANTHROPIC_API_KEY/CULPRIT_RCA_MODEL env vars.", exc_info=True,
        )
        return None


def build_live_collectors(session):
    """Wires every collector with whatever's saved on the /culprit/settings
    screen (falls back to DefaultAzureCredential / env-var Datadog auth
    if nothing was ever saved there - same behavior as before that screen
    existed). Not cached: each live run should pick up settings saved
    since the last one, and a fresh set of per-subscription Compute
    clients per run avoids reusing a credential across an unrelated
    request."""
    from culprit.collectors.azure_auth import build_credential
    from culprit.collectors.azure_control_plane import AzureControlPlaneCollector
    from culprit.collectors.azure_monitor import AzureMonitorCollector
    from culprit.collectors.datadog_collector import DatadogCollector
    from culprit.collectors.guest_linux import GuestLinuxCollector
    from culprit.collectors.guest_windows import GuestWindowsCollector
    from culprit.db import repository
    from culprit.models.evidence import Source

    azure_cfg = repository.load_azure_settings(session)
    datadog_cfg = repository.load_datadog_settings(session)
    credential = build_credential(azure_cfg)

    collectors = {
        Source.AZURE_CONTROL_PLANE: AzureControlPlaneCollector(credential=credential),
        Source.GUEST_LINUX: GuestLinuxCollector(credential=credential),
        Source.GUEST_WINDOWS: GuestWindowsCollector(credential=credential),
        Source.DATADOG_METRIC: DatadogCollector(settings=datadog_cfg),
    }
    if azure_cfg.log_analytics_workspace_id:
        collectors[Source.AZURE_MONITOR] = AzureMonitorCollector(
            azure_cfg.log_analytics_workspace_id, credential=credential
        )
    return collectors, azure_cfg, credential
