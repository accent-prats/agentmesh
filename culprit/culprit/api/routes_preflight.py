"""Read access to the most recent pre-flight scan (proposal Section 10) -
what culprit/scheduler/cron.py::pre_flight_check populates, and what
culprit/api/routes_chat.py's "which machines will fail next" answers read
from."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from culprit.api import deps
from culprit.models.preflight import PreflightFinding

router = APIRouter(prefix="/preflight", tags=["preflight"])


class PreflightResponse(BaseModel):
    findings: list[PreflightFinding]


@router.get("", response_model=PreflightResponse)
def get_preflight_findings() -> PreflightResponse:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        findings = repository.latest_preflight_findings(session)
    return PreflightResponse(findings=findings)
