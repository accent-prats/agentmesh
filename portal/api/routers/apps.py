"""
GET /api/apps — returns the apps the current user can access,
with display metadata for the app launcher UI.
"""
import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from portal.dependencies import get_current_user

router = APIRouter()

_APP_REGISTRY = {
    "culprit": {
        "id": "culprit",
        "name": "Culprit",
        "full_name": "Culprit — Patch Failure RCA Agent",
        "description": "Autonomous root-cause analysis for failed Azure Update Manager patch deployments — collapses hundreds of failures into a handful of distinct causes, settles the obvious ones with a deterministic rule engine, and hands the ambiguous tail to Claude for deep reasoning and remediation guidance.",
        "icon": "search",
        "color": "rose",
        "url_env": "CULPRIT_PUBLIC_URL",
        "default_url": "/culprit/",
        "hidden": False,
    },
}


class AppInfo(BaseModel):
    id: str
    name: str
    full_name: str
    description: str
    icon: str
    color: str
    url: str


@router.get("", response_model=list[AppInfo])
async def list_accessible_apps(user=Depends(get_current_user)):
    """Return app metadata for each app the current user can access.

    Admin users automatically see all registered apps regardless of
    the app_access list stored in the DB (covers newly added apps).
    """
    if user.role in ("admin", "ci_service"):
        # Admins see everything — no need to update individual users when new apps deploy
        accessible = list(_APP_REGISTRY.keys())
    else:
        accessible = user.app_access or []
    result = []
    for app_id in accessible:
        meta = _APP_REGISTRY.get(app_id)
        if not meta or meta.get("hidden", False):
            continue
        url = os.environ.get(meta["url_env"], meta["default_url"])
        result.append(AppInfo(
            id=meta["id"],
            name=meta["name"],
            full_name=meta["full_name"],
            description=meta["description"],
            icon=meta["icon"],
            color=meta["color"],
            url=url,
        ))
    return result
