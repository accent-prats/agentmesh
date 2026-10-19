"""The durable pipeline runner (proposal Section 4 & 13).

Given a PatchRun and the EvidenceBundles already collected for its failed
machines, this drives: cluster -> rule engine -> (deep RCA for whatever the
rules didn't settle, with one targeted re-collection pass if the agent asks
for more evidence) -> advisor -> persist -> fleet report.

Every stage is checkpointed to the database (culprit/db) as it completes,
so a crash mid-cycle resumes from the last completed stage rather than
re-running collection from scratch - "durable" in the sense the proposal
means it, without pulling in a separate workflow engine.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from sqlalchemy.orm import sessionmaker

from culprit.collectors.base import CollectionResult
from culprit.db import repository
from culprit.db.models import RunStage
from culprit.models.cluster import Cluster
from culprit.models.evidence import EvidenceBundle, Source
from culprit.models.patch_run import PatchRun
from culprit.models.rca import RCAResult
from culprit.pipeline.advisor import RecurrenceInfo, advise
from culprit.pipeline.fingerprint import cluster_run
from culprit.pipeline.normalize import merge_recollection
from culprit.pipeline.rca_agent import DeepRCAAgent
from culprit.pipeline.rules import evaluate_rules
from culprit.retrieval.store import RetrievalStore

log = logging.getLogger(__name__)

# (bundle, missing_evidence) -> {source: CollectionResult} - every applicable
# collector's full, fresh result for this one targeted recollection pass,
# not just a flattened events list (see pipeline/collection.py::
# recollect_targeted's own docstring for why the full shape matters).
RecollectFn = Callable[[EvidenceBundle, list[str]], dict[Source, CollectionResult]]


@dataclass
class DiagnosedCluster:
    cluster: Cluster
    result: RCAResult
    recurrence: RecurrenceInfo


@dataclass
class PipelineOutput:
    run: PatchRun
    diagnosed: list[DiagnosedCluster]


class Pipeline:
    def __init__(
        self,
        session_factory: sessionmaker,
        rca_agent: DeepRCAAgent | None = None,
        retrieval_store: RetrievalStore | None = None,
        recollect_fn: RecollectFn | None = None,
    ):
        self.session_factory = session_factory
        self.rca_agent = rca_agent
        self.retrieval_store = retrieval_store
        self.recollect_fn = recollect_fn

    def run(self, patch_run: PatchRun, failed_bundles: list[EvidenceBundle]) -> PipelineOutput:
        try:
            with self.session_factory() as session:
                repository.save_run(session, patch_run, stage=RunStage.STARTED)

                clusters = cluster_run(patch_run.run_id, failed_bundles)
                for cluster in clusters:
                    repository.save_cluster(session, cluster)
                repository.update_run_stage(session, patch_run.run_id, RunStage.CLUSTERED)

                bundle_by_vm = {b.machine.vm_id: b for b in failed_bundles}
                history = repository.historical_cluster_keys(session, patch_run.run_id)

                diagnosed: list[DiagnosedCluster] = []
                for cluster in clusters:
                    representative = bundle_by_vm[cluster.representative_vm_id]
                    result, representative = self._diagnose_one(cluster, representative)
                    # A recollection pass (see _diagnose_one) only ever targets the
                    # cluster's representative machine - update the shared dict so
                    # both the persisted outcome below and anything else reading it
                    # this run see the augmented bundle, not the pre-recollection one.
                    bundle_by_vm[cluster.representative_vm_id] = representative
                    result, recurrence = advise(result, cluster.cluster_key, history)
                    repository.save_rca_result(session, result, consecutive_cycles=recurrence.consecutive_cycles)
                    member_bundles = [bundle_by_vm[m.vm_id] for m in cluster.members]
                    repository.save_machine_outcomes(session, patch_run.run_id, cluster.cluster_key, member_bundles)
                    diagnosed.append(DiagnosedCluster(cluster=cluster, result=result, recurrence=recurrence))

                repository.update_run_stage(session, patch_run.run_id, RunStage.DIAGNOSED)
                repository.update_run_stage(
                    session,
                    patch_run.run_id,
                    RunStage.COMPLETE,
                    ended_at=datetime.now(patch_run.started_at.tzinfo),
                    failed_machines=len(failed_bundles),
                )
        except Exception:
            # Found in review 2026-09-27: RunStage.FAILED was defined but
            # never actually set anywhere - a crash partway through (a
            # rate-limited/erroring Claude call, a DB error, an exception
            # surfacing from recollect_fn's real Azure calls) left the run
            # stuck at CLUSTERED forever, with nothing distinguishing
            # "still running" from "died an hour ago". A fresh session,
            # since the one above may be mid a failed transaction.
            try:
                with self.session_factory() as failure_session:
                    repository.update_run_stage(failure_session, patch_run.run_id, RunStage.FAILED)
            except Exception:
                log.exception("Failed to mark run %s as FAILED after an error", patch_run.run_id)
            raise

        return PipelineOutput(run=patch_run, diagnosed=diagnosed)

    def _diagnose_one(self, cluster: Cluster, representative: EvidenceBundle) -> tuple[RCAResult, EvidenceBundle]:
        """Returns the RCAResult AND the representative's bundle, which a
        recollection pass below may have augmented - the caller (run())
        must persist THIS returned bundle, not the one it passed in, or a
        recollection pass's real findings never reach save_machine_
        outcomes() (found 2026-10-19 from a real production run - see
        normalize.py::merge_recollection's own docstring for the full
        story)."""
        rule_result = evaluate_rules(cluster, representative)
        if rule_result is not None:
            return rule_result, representative

        if self.rca_agent is None:
            from culprit.models.rca import ResultOrigin
            from culprit.models.taxonomy import CauseFamily

            return RCAResult(
                cluster_id=cluster.cluster_id,
                origin=ResultOrigin.DEEP_RCA,
                cause_family=CauseFamily.UNRESOLVED,
                title="No deep RCA agent configured",
                causal_chain=[],
                confidence=0.0,
                missing_evidence=["Deep RCA agent not configured for this pipeline run"],
            ), representative

        near_misses = _describe_near_misses(cluster, representative)
        query = f"{cluster.fingerprint.error_code_normalized} {cluster.fingerprint.failing_target} {cluster.fingerprint.os_family.value}"
        retrieval_context = self.retrieval_store.render_context(query) if self.retrieval_store else ""

        result = self.rca_agent.diagnose(cluster, representative, near_misses, retrieval_context)

        if result.missing_evidence and self.recollect_fn is not None:
            new_results = self.recollect_fn(representative, result.missing_evidence)
            if new_results:
                representative = merge_recollection(representative, new_results)
                result = self.rca_agent.diagnose(cluster, representative, near_misses, retrieval_context)

        return result, representative


def _describe_near_misses(cluster: Cluster, representative: EvidenceBundle) -> list[str]:
    """Cheap re-check of each rule's precondition, described in prose, so
    the RCA agent knows what the rule engine already considered and ruled
    out - it should reason about *why* those didn't fire, not re-derive it
    from scratch."""
    from culprit.pipeline.rules import RuleContext, _has_detail_flag

    ctx = RuleContext(cluster=cluster, representative=representative)
    notes = []
    disk_flag, _ = _has_detail_flag(representative, "disk_low")
    if disk_flag:
        notes.append("disk_low precondition present but no corroborating write-failure evidence - disk-exhaustion rule abstained")
    lock_flag, _ = _has_detail_flag(representative, "lock_held")
    if lock_flag and cluster.fingerprint.error_code_normalized != "package_manager_failure":
        notes.append("lock_held precondition present but error code doesn't match - package-lock rule abstained")
    return notes
