"""
Portal API — unified authentication and app-launcher for the AgentMesh platform.

Serves the shared login and app-access endpoints that are used by the portal UI.
Issues JWTs shared across all platform apps so tokens are valid
across all platform apps without a separate token exchange.

Routes:
  POST /api/auth/login             — issue access + refresh tokens
  POST /api/auth/refresh           — rotate access token
  GET  /api/auth/me                — current user profile + app_access
  GET  /api/apps                   — apps the current user can access
  PUT  /api/users/{id}/apps        — update a user's app_access list (admin)
  *    /api/ai-providers/*         — platform-wide AI provider config (admin),
                                      plus a service-to-service resolver other
                                      apps call to build a real client
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from portal.api.routers import ai_providers, auth, apps
from portal.db import bootstrap
from portal.logging_config import configure_logging, get_logger
from shared.src.feature_flags import FlagMiddleware, GrowthBookClient, set_client

configure_logging()
log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("portal_starting")

    await bootstrap()

    # Initialize GrowthBook feature-flag client (non-fatal if unreachable)
    gb_client = GrowthBookClient(
        api_host=os.getenv("GROWTHBOOK_API_HOST", "http://growthbook:3100"),
        client_key=os.getenv("GROWTHBOOK_CLIENT_KEY", "sdk-"),
        refresh_interval=int(os.getenv("GROWTHBOOK_REFRESH_INTERVAL", "60")),
    )
    await gb_client.initialize()
    set_client(gb_client)

    yield

    await gb_client.shutdown()
    log.info("portal_shutdown")


app = FastAPI(
    title="AgentMesh Portal",
    description="Unified authentication and app-launcher for all AgentMesh apps.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    FlagMiddleware,
    app_name="portal",
    environment=os.getenv("ENVIRONMENT", "production"),
)

app.include_router(auth.router,         prefix="/api/auth",          tags=["Auth"])
app.include_router(apps.router,         prefix="/api/apps",          tags=["Apps"])
app.include_router(ai_providers.router, prefix="/api/ai-providers",  tags=["AI Providers"])


@app.get("/api/health", include_in_schema=False)
async def health():
    return JSONResponse({"status": "ok", "service": "portal"})
