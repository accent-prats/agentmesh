"""Engineer feedback and the precision-gate models it feeds.

Every RCA card carries a verdict control (proposal Section 11). This is
the product's core instrumentation, not a satisfaction survey: corrections
become retrieval examples, and precision is tracked per CauseFamily - that
per-family number *is* the Phase 2 promotion gate.
"""
from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field

from culprit.models.taxonomy import CauseFamily


class VerdictValue(str, enum.Enum):
    CORRECT = "correct"
    PARTIALLY_CORRECT = "partially_correct"
    WRONG = "wrong"


class Verdict(BaseModel):
    cluster_id: str
    cause_family: CauseFamily
    verdict: VerdictValue
    reviewer: str
    reviewed_at: datetime
    correction_note: str = ""


class FamilyPrecision(BaseModel):
    """Precision for one CauseFamily, computed over its reviewed instances.
    `correct` and `partially_correct` both count as a hit for the promotion
    gate's arithmetic (proposal: "≥95% over at least 50 reviewed instances"),
    while remaining separately visible for the trend view - a family that is
    95% "partially correct" deserves a different look than one at 95% clean.
    """

    cause_family: CauseFamily
    sample_size: int
    correct: int
    partially_correct: int
    wrong: int

    @property
    def precision(self) -> float:
        if self.sample_size == 0:
            return 0.0
        return (self.correct + self.partially_correct) / self.sample_size

    @property
    def clean_precision(self) -> float:
        """Same computation counting only exact 'correct' verdicts - the
        stricter number worth watching even though it isn't the gate."""
        if self.sample_size == 0:
            return 0.0
        return self.correct / self.sample_size

    def meets_promotion_bar(self, threshold: float, min_sample: int) -> bool:
        return self.sample_size >= min_sample and self.precision >= threshold


def compute_family_precision(verdicts: list[Verdict]) -> dict[CauseFamily, FamilyPrecision]:
    buckets: dict[CauseFamily, list[Verdict]] = {}
    for v in verdicts:
        buckets.setdefault(v.cause_family, []).append(v)

    out: dict[CauseFamily, FamilyPrecision] = {}
    for family, vs in buckets.items():
        out[family] = FamilyPrecision(
            cause_family=family,
            sample_size=len(vs),
            correct=sum(1 for v in vs if v.verdict == VerdictValue.CORRECT),
            partially_correct=sum(1 for v in vs if v.verdict == VerdictValue.PARTIALLY_CORRECT),
            wrong=sum(1 for v in vs if v.verdict == VerdictValue.WRONG),
        )
    return out
