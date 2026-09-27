from __future__ import annotations

from datetime import datetime, timezone

from culprit.models.taxonomy import PROMOTION_MIN_SAMPLE, PROMOTION_PRECISION_THRESHOLD, CauseFamily
from culprit.models.verdict import Verdict, VerdictValue, compute_family_precision


def _verdict(family: CauseFamily, value: VerdictValue) -> Verdict:
    return Verdict(
        cluster_id="c", cause_family=family, verdict=value, reviewer="alice",
        reviewed_at=datetime.now(timezone.utc),
    )


def test_precision_counts_correct_and_partial_as_hits():
    verdicts = [
        _verdict(CauseFamily.CAPACITY, VerdictValue.CORRECT),
        _verdict(CauseFamily.CAPACITY, VerdictValue.PARTIALLY_CORRECT),
        _verdict(CauseFamily.CAPACITY, VerdictValue.WRONG),
        _verdict(CauseFamily.CAPACITY, VerdictValue.CORRECT),
    ]
    by_family = compute_family_precision(verdicts)
    fp = by_family[CauseFamily.CAPACITY]
    assert fp.sample_size == 4
    assert fp.precision == 0.75  # 3/4 count as a hit
    assert fp.clean_precision == 0.5  # 2/4 are strictly "correct"


def test_families_tracked_independently():
    verdicts = [
        _verdict(CauseFamily.CAPACITY, VerdictValue.CORRECT),
        _verdict(CauseFamily.POST_PATCH_REGRESSION, VerdictValue.WRONG),
    ]
    by_family = compute_family_precision(verdicts)
    assert by_family[CauseFamily.CAPACITY].precision == 1.0
    assert by_family[CauseFamily.POST_PATCH_REGRESSION].precision == 0.0


def test_promotion_bar_requires_both_precision_and_sample_size():
    verdicts = [_verdict(CauseFamily.CAPACITY, VerdictValue.CORRECT) for _ in range(10)]
    fp = compute_family_precision(verdicts)[CauseFamily.CAPACITY]
    assert fp.precision == 1.0
    # High precision but too few samples must not clear the gate.
    assert fp.meets_promotion_bar(PROMOTION_PRECISION_THRESHOLD, PROMOTION_MIN_SAMPLE) is False


def test_promotion_bar_clears_with_enough_precise_samples():
    verdicts = [_verdict(CauseFamily.CAPACITY, VerdictValue.CORRECT) for _ in range(48)]
    verdicts += [_verdict(CauseFamily.CAPACITY, VerdictValue.PARTIALLY_CORRECT) for _ in range(2)]
    fp = compute_family_precision(verdicts)[CauseFamily.CAPACITY]
    assert fp.sample_size == 50
    assert fp.precision == 1.0
    assert fp.meets_promotion_bar(PROMOTION_PRECISION_THRESHOLD, PROMOTION_MIN_SAMPLE) is True


def test_promotion_bar_fails_below_threshold_even_with_sample_size():
    verdicts = [_verdict(CauseFamily.CAPACITY, VerdictValue.CORRECT) for _ in range(40)]
    verdicts += [_verdict(CauseFamily.CAPACITY, VerdictValue.WRONG) for _ in range(10)]
    fp = compute_family_precision(verdicts)[CauseFamily.CAPACITY]
    assert fp.sample_size == 50
    assert fp.precision == 0.8
    assert fp.meets_promotion_bar(PROMOTION_PRECISION_THRESHOLD, PROMOTION_MIN_SAMPLE) is False


def test_empty_sample_has_zero_precision_and_never_promotes():
    from culprit.models.verdict import FamilyPrecision

    fp = FamilyPrecision(cause_family=CauseFamily.CAPACITY, sample_size=0, correct=0, partially_correct=0, wrong=0)
    assert fp.precision == 0.0
    assert fp.meets_promotion_bar(PROMOTION_PRECISION_THRESHOLD, PROMOTION_MIN_SAMPLE) is False
