"""Verdict submission and the precision report the Phase 2 gate reads
from (proposal Section 11)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from culprit.api import deps
from culprit.config import settings
from culprit.models.taxonomy import CauseFamily
from culprit.models.verdict import Verdict, VerdictValue, compute_family_precision

router = APIRouter(tags=["verdicts"])


class SubmitVerdictBody(BaseModel):
    cluster_id: str
    cause_family: CauseFamily
    verdict: VerdictValue
    reviewer: str
    correction_note: str = ""


@router.post("/verdicts")
def submit_verdict(body: SubmitVerdictBody) -> dict:
    from culprit.db import repository
    from culprit.memory import episodic as memory_episodic

    verdict = Verdict(
        cluster_id=body.cluster_id,
        cause_family=body.cause_family,
        verdict=body.verdict,
        reviewer=body.reviewer,
        reviewed_at=datetime.now(timezone.utc),
        correction_note=body.correction_note,
    )
    with deps.get_session_factory()() as session:
        repository.save_verdict(session, verdict)
        found = repository.get_rca_result(session, body.cluster_id)

    if found is not None:
        cluster_key, result = found
        store = deps.get_retrieval_store()
        if body.verdict == VerdictValue.CORRECT:
            # The compounding mechanism the proposal describes (Section 7):
            # a confirmed-correct RCA becomes a retrieval target for the
            # next cycle's deep RCA agent, so the system gets sharper on
            # this estate's own quirks over time. Deliberately not
            # "partially_correct" too - a correction the reviewer flagged
            # as only partly right isn't a clean example to learn from
            # without editing it first, which is what correction_note is
            # for, not automatic ingestion.
            #
            # Exactly one of these two, never both: when memory is active
            # (remember_verdict exists), the confirmed RCA belongs in mem0
            # only - writing it to the vendor TF-IDF store too would make
            # render_context() return the same finding twice (once via
            # term overlap, once via semantic similarity) for any query
            # that matches it, which is what happened before this comment
            # existed and is exactly the kind of thing
            # tests/test_memory.py::TestNoDuplicateEvidence now pins.
            if hasattr(store, "remember_verdict"):
                store.remember_verdict(verdict, cluster_key, result)
            else:
                store.add_resolved_incident(
                    cluster_key=cluster_key,
                    title=result.title,
                    summary=memory_episodic.compose_summary(result),
                    tags=[result.cause_family.value, *([body.correction_note] if body.correction_note else [])],
                )
        elif body.verdict == VerdictValue.WRONG:
            # The inverse: a later verdict says a previously-remembered
            # finding for this same recurring cause was wrong - forget it
            # rather than let a confirmed-wrong finding keep being
            # retrieved as if it were institutional knowledge.
            store.forget_resolved_incident(cluster_key)

    return {"ok": True}


def _precision_payload() -> dict:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        verdicts = repository.all_verdicts(session)

    by_family = compute_family_precision(verdicts)
    return {
        "threshold": settings.promotion_precision_threshold,
        "min_sample": settings.promotion_min_sample,
        "families": {
            family.value: {
                "sample_size": fp.sample_size,
                "precision": round(fp.precision, 4),
                "clean_precision": round(fp.clean_precision, 4),
                "meets_promotion_bar": fp.meets_promotion_bar(
                    settings.promotion_precision_threshold, settings.promotion_min_sample
                ),
            }
            for family, fp in by_family.items()
        },
    }


@router.get("/precision")
def get_precision() -> dict:
    """Per-family precision plus whether each family currently meets the
    Phase 2 promotion bar - the single view the proposal's gate (Section
    11) is decided from."""
    return _precision_payload()


@router.get("/precision.html")
def get_precision_html():
    """The human-readable rendering of the same data GET /precision
    returns - linked from the sidebar so the gate is somewhere a reviewer
    actually looks, not just an API response nobody opens."""
    from fastapi.responses import HTMLResponse

    from culprit.reporting.render import render_precision_html

    return HTMLResponse(render_precision_html(_precision_payload()))
