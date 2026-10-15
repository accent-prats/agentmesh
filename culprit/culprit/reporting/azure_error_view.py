"""Display-only view over `PatchOutcome.error_details`
(models/evidence.py::AzureApiErrorDetail) - Azure's own structured
`ApiError.details[]` for a failed patch install, surfaced on the machine
drill-down page as its own card, parallel to extension_status_view.py's
"Patch extension report" card but for the control-plane equivalent
evidence. No badge-color variance like that card's success/warning/error
spread - every entry here is, by definition, something Azure's own patch
installation result reported as an error."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AzureErrorDetailView:
    code: str | None
    message: str
    target: str | None


def build_azure_error_views(error_details: list) -> list[AzureErrorDetailView]:
    """`error_details` is a list of `AzureApiErrorDetail` (or anything
    with the same code/message/target attributes, e.g. a dict loaded
    straight back from a JSON column) - accepts either so this can be fed
    either `PatchOutcome.error_details` directly or a raw persisted list."""
    views = []
    for d in error_details:
        code = d.get("code") if isinstance(d, dict) else d.code
        message = d.get("message") if isinstance(d, dict) else d.message
        target = d.get("target") if isinstance(d, dict) else d.target
        views.append(AzureErrorDetailView(code=code, message=message or "(no message)", target=target))
    return views
