"""
FastAPI dependency — injects the per-request GrowthBook evaluator.

Usage in any router:

    from growthbook import GrowthBook
    from fastapi import Depends
    from shared.src.feature_flags import get_feature_flags

    @router.get("/my-endpoint")
    async def handler(flags: GrowthBook = Depends(get_feature_flags)):
        # Boolean flag
        if flags.is_on("portal.admin.bulk-user-import"):
            return await new_import_flow(...)

        return await legacy_flow(...)

Flag naming convention:  {app}.{component}.{feature-name}
Examples:
    portal.admin.bulk-user-import
    portal.launcher.maintenance-banner
    shared.beta.early-access            ← cross-app value flag
"""
from __future__ import annotations

from growthbook import GrowthBook
from starlette.requests import Request


def get_feature_flags(request: Request) -> GrowthBook:
    """Return the GrowthBook evaluator attached by FlagMiddleware.

    Falls back to an empty instance (all flags → defaults) when middleware
    has not run, e.g. on unauthenticated pre-flight or health-check routes.
    """
    flags = getattr(request.state, "flags", None)
    if flags is None:
        return GrowthBook(attributes={}, features={})
    return flags
