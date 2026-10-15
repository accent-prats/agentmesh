"""Display-only view over `EvidenceBundle.patch_extension_status` findings
(collectors/patch_extension_status.py) - badge color/icon per status, for
the machine drill-down page's "Patch extension report" card. This is
presentation logic over already-structured data, not another parsing pass -
the parsing already happened at collection time."""
from __future__ import annotations

from dataclasses import dataclass

_STATUS_DISPLAY: dict[str, tuple[str, str, str]] = {  # status -> (label, badge color, icon)
    "success": ("Success", "emerald", "check-circle"),
    "error": ("Error", "red", "x-circle"),
    "warning": ("Warning", "amber", "alert-triangle"),
    "transitioning": ("Transitioning", "sky", "loader"),
}
_DEFAULT_DISPLAY = ("Unknown", "gray", "help-circle")


@dataclass(frozen=True)
class ExtensionFindingView:
    extension_name: str
    extension_version: str | None
    operation: str | None
    status: str
    status_label: str
    badge_color: str
    icon: str
    code: object
    message: str
    substatus_name: str | None
    raw_status_json: str | None


def build_extension_finding_views(findings: list[dict]) -> list[ExtensionFindingView]:
    views = []
    for f in findings:
        label, color, icon = _STATUS_DISPLAY.get(f.get("status"), _DEFAULT_DISPLAY)
        views.append(ExtensionFindingView(
            extension_name=f.get("extension_name") or "(unknown extension)",
            extension_version=f.get("extension_version"),
            operation=f.get("operation"),
            status=f.get("status") or "unknown",
            status_label=label, badge_color=color, icon=icon,
            code=f.get("code"), message=f.get("message") or "",
            substatus_name=f.get("substatus_name"),
            raw_status_json=f.get("raw_status_json"),
        ))
    return views
