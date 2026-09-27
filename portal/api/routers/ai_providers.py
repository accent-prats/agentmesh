"""Platform-wide AI provider configuration - admin-only, shared by every
app that needs an LLM call. Culprit's deep RCA agent is the one consumer
today; a future app gets the same screen and the same providers for free
instead of re-implementing this.

Two audiences, two different auth models on the same data:
  - GET/PUT/test/active below: a human admin, browser session, JWT with
    `role == "admin"` (`portal/dependencies.py::require_admin`).
  - `/resolved-active`: another app's backend calling in at request time
    to actually build a client and make the model call - a short-lived
    `type: "service"` token that app mints itself
    (`portal/security.py::create_service_token`), not a user session
    (`portal/dependencies.py::require_service`). This is the only route
    that ever returns a decrypted `api_key` - the admin-facing views never
    echo one back, same rule Culprit's own settings screens follow.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.crypto import decrypt, encrypt
from portal.db import AIProviderSetting, get_db
from portal.dependencies import require_admin, require_service
from shared.src.llm.catalog import PROVIDER_CATALOG
from shared.src.llm.credential_test import test_ai_provider_credentials

router = APIRouter()

_ACTIVE_ROW = "__active__"


class AIProviderInput(BaseModel):
    base_url: str = ""
    model: str = ""
    api_key: str = ""
    api_version: str = ""
    deployment: str = ""


class AIProviderView(BaseModel):
    provider: str
    label: str = ""
    base_url: str = ""
    model: str = ""
    model_options: list[str] = Field(default_factory=list)
    api_version: str = ""
    deployment: str = ""
    api_key_configured: bool = False
    requires_api_key: bool = True
    is_azure: bool = False
    configured: bool = False
    last_tested_at: str | None = None
    last_test_ok: bool | None = None
    last_test_message: str = ""


class AIProvidersView(BaseModel):
    active_provider: str = ""  # "" - no default; only set once an admin picks one
    providers: dict[str, AIProviderView] = Field(default_factory=dict)


class ActiveProviderInput(BaseModel):
    provider: str


class ResolvedActiveProvider(BaseModel):
    """What another app actually needs to build a client - never exposed
    to the admin UI, only to `require_service`-gated callers."""
    provider: str = ""
    api_key: str = ""
    base_url: str = ""
    model: str = ""
    api_version: str = ""
    deployment: str = ""


def _require_known_provider(provider: str) -> None:
    if provider not in PROVIDER_CATALOG:
        raise HTTPException(status_code=404, detail=f"Unknown AI provider: {provider!r}")


async def _get_row(db: AsyncSession, provider: str) -> AIProviderSetting | None:
    result = await db.execute(select(AIProviderSetting).where(AIProviderSetting.provider == provider))
    return result.scalar_one_or_none()


def _view(provider: str, row: AIProviderSetting | None) -> AIProviderView:
    spec = PROVIDER_CATALOG.get(provider)
    d = row.data_json if row else {}
    base_url = d.get("base_url") or (spec.default_base_url if spec else "")
    api_key_configured = bool(d.get("api_key_ciphertext"))
    requires_key = spec.requires_api_key if spec else True
    requires_url = spec.requires_base_url if spec else True
    return AIProviderView(
        provider=provider,
        label=spec.label if spec else provider,
        base_url=base_url,
        model=d.get("model") or (spec.default_model if spec else ""),
        model_options=list(spec.model_options) if spec else [],
        api_version=d.get("api_version", ""),
        deployment=d.get("deployment", ""),
        api_key_configured=api_key_configured,
        requires_api_key=requires_key,
        is_azure=spec.is_azure if spec else False,
        configured=(bool(base_url) or not requires_url) and (api_key_configured or not requires_key),
        last_tested_at=row.last_tested_at.isoformat() if row and row.last_tested_at else None,
        last_test_ok=row.last_test_ok if row else None,
        last_test_message=row.last_test_message if row else "",
    )


@router.get("", response_model=AIProvidersView)
async def get_ai_providers(db: AsyncSession = Depends(get_db), _=Depends(require_admin)) -> AIProvidersView:
    active_row = await _get_row(db, _ACTIVE_ROW)
    active_provider = (active_row.data_json.get("provider", "") if active_row else "")
    providers = {}
    for provider in PROVIDER_CATALOG:
        providers[provider] = _view(provider, await _get_row(db, provider))
    return AIProvidersView(active_provider=active_provider, providers=providers)


# Registered before /{provider} - path routing matches by registration
# order, not specificity, so this literal path must come first or
# "active" would be swallowed as a provider id and 404 below.
@router.put("/active", response_model=AIProvidersView)
async def put_active_provider(
    body: ActiveProviderInput, db: AsyncSession = Depends(get_db), _=Depends(require_admin),
) -> AIProvidersView:
    """`body.provider == ""` intentionally clears the active provider back
    to "nothing configured" - every consuming app's fallback (Culprit:
    ANTHROPIC_API_KEY) takes over again. There is no default to fall back
    to *within this table*, so "picked nothing" has to be a real, valid
    state an admin can return to, not just the one they start in."""
    if body.provider:
        _require_known_provider(body.provider)
    row = await _get_row(db, _ACTIVE_ROW)
    if row is None:
        db.add(AIProviderSetting(provider=_ACTIVE_ROW, data_json={"provider": body.provider}))
    else:
        row.data_json = {"provider": body.provider}
    await db.flush()
    return await get_ai_providers(db=db, _=_)


@router.put("/{provider}", response_model=AIProviderView)
async def put_ai_provider(
    provider: str, body: AIProviderInput, db: AsyncSession = Depends(get_db), _=Depends(require_admin),
) -> AIProviderView:
    """Same leave-alone-if-blank rule on `api_key` as Culprit's own
    Azure/Datadog settings screen: a blank key on an update means "keep
    whatever's already saved", never "erase it"."""
    _require_known_provider(provider)
    row = await _get_row(db, provider)
    existing_ciphertext = row.data_json.get("api_key_ciphertext", "") if row else ""
    data = {
        "base_url": body.base_url,
        "model": body.model,
        "api_version": body.api_version,
        "deployment": body.deployment,
        "api_key_ciphertext": encrypt(body.api_key) if body.api_key else existing_ciphertext,
    }
    if row is None:
        row = AIProviderSetting(provider=provider, data_json=data)
        db.add(row)
    else:
        row.data_json = data
    await db.flush()
    return _view(provider, row)


@router.post("/{provider}/test")
async def test_ai_provider(
    provider: str, body: AIProviderInput | None = None, db: AsyncSession = Depends(get_db), _=Depends(require_admin),
) -> dict:
    _require_known_provider(provider)
    row = await _get_row(db, provider)
    d = row.data_json if row else {}
    api_key = body.api_key if body and body.api_key else decrypt(d.get("api_key_ciphertext", ""))
    base_url = (body.base_url if body else "") or d.get("base_url", "")
    model = (body.model if body else "") or d.get("model", "")
    api_version = (body.api_version if body else "") or d.get("api_version", "")
    deployment = (body.deployment if body else "") or d.get("deployment", "")

    ok, message = test_ai_provider_credentials(
        provider, api_key=api_key, base_url=base_url, model=model, api_version=api_version, deployment=deployment,
    )

    from datetime import datetime, timezone

    if row is None:
        row = AIProviderSetting(provider=provider, data_json=d)
        db.add(row)
    row.last_tested_at = datetime.now(timezone.utc)
    row.last_test_ok = ok
    row.last_test_message = message
    await db.flush()
    return {"ok": ok, "message": message}


@router.get("/resolved-active", response_model=ResolvedActiveProvider)
async def get_resolved_active_provider(
    db: AsyncSession = Depends(get_db), _service: str = Depends(require_service),
) -> ResolvedActiveProvider:
    """The one endpoint that returns a decrypted `api_key` - only to a
    trusted peer app (`require_service`), never to the admin UI. Returns
    an all-blank `ResolvedActiveProvider` (provider="") when no admin has
    ever picked one - there is no default to fall back to here; the
    caller decides what "nothing configured" means for it (Culprit falls
    back to its own legacy env var, see api/deps.py::get_rca_agent)."""
    active_row = await _get_row(db, _ACTIVE_ROW)
    provider = active_row.data_json.get("provider", "") if active_row else ""
    if not provider:
        return ResolvedActiveProvider()

    row = await _get_row(db, provider)
    spec = PROVIDER_CATALOG.get(provider)
    d = row.data_json if row else {}
    return ResolvedActiveProvider(
        provider=provider,
        api_key=decrypt(d.get("api_key_ciphertext", "")),
        base_url=d.get("base_url") or (spec.default_base_url if spec else ""),
        model=d.get("model") or (spec.default_model if spec else ""),
        api_version=d.get("api_version", ""),
        deployment=d.get("deployment", ""),
    )
