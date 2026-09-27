"""RunStage.FAILED - found in review 2026-09-27: the enum value existed
but nothing ever set it, so a crash partway through a run left it stuck
at CLUSTERED forever with no way to tell "still running" from "died"."""
from __future__ import annotations

import pytest

from culprit.db import repository
from culprit.db.models import RunRecord, RunStage
from culprit.demo.generate_scenario import build_scenario
from culprit.pipeline.orchestrator import Pipeline


class ExplodingRCAAgent:
    """Raises on the first diagnose() call - simulates a Claude API error,
    a rate limit, or any other mid-run failure in the deep-RCA path."""

    def diagnose(self, cluster, representative, near_misses=None, retrieval_context=""):
        raise RuntimeError("simulated Anthropic API failure")


def test_a_crash_mid_run_marks_the_run_failed_not_stuck(session_factory):
    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=ExplodingRCAAgent())

    with pytest.raises(RuntimeError, match="simulated Anthropic API failure"):
        pipeline.run(run, bundles)

    with session_factory() as session:
        record = session.get(RunRecord, run.run_id)
        assert record is not None
        assert record.stage == RunStage.FAILED.value


def test_failed_run_still_has_its_clusters_persisted(session_factory):
    """The crash happens after clustering, so that work shouldn't be lost -
    only the diagnosis stage is incomplete."""
    run, bundles = build_scenario()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=ExplodingRCAAgent())

    with pytest.raises(RuntimeError):
        pipeline.run(run, bundles)

    with session_factory() as session:
        record = session.get(RunRecord, run.run_id)
        assert len(record.clusters) == 6  # the demo scenario's 6 clusters, per test_pipeline_end_to_end.py
