"""End-to-end: a targeted recollection pass that genuinely recovers real
guest evidence must actually reach what gets persisted and shown on the
machine page - not just the RCA agent's own second-pass prompt.

Found 2026-10-19 from a real production run (tcx-tenant,
tcx-tenant-t30bc57a-prd-WindowsServer1-vm): the first RCA call hallucinated
a 'vendor_doc' evidence_ref, got rejected, triggered a targeted
recollection on guest_windows, which completed cleanly - but the machine
page still showed every guest check as "not collected", because
pipeline/orchestrator.py's recollection pass only ever fed a transient
bundle to the RCA agent's second diagnose() call, never back into what
db/repository.py::save_machine_outcomes() actually persists. Fixed via
pipeline/normalize.py::merge_recollection (unit-tested directly in
test_merge_recollection.py) wired through orchestrator.py/collection.py.
This test proves the whole path end to end, through a real in-memory DB,
the same way a real live run would exercise it."""
from __future__ import annotations

from datetime import datetime, timezone

from culprit.collectors.base import CollectionResult
from culprit.db import repository
from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.models.patch_run import PatchRun, TriggerMode
from culprit.models.rca import RCAResult, ResultOrigin
from culprit.models.taxonomy import CauseFamily
from culprit.pipeline.orchestrator import Pipeline

_DISK_LABEL = "disk usage"


def _machine() -> MachineIdentity:
    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )


def _first_pass_bundle() -> EvidenceBundle:
    """Models the real reported shape: guest_linux's first pass got nothing
    at all (timed out), azure_control_plane succeeded. No rule in rules.py
    recognizes this error code, so it falls through to the (fake) deep RCA
    agent below."""
    return EvidenceBundle(
        run_id="run-1", machine=_machine(),
        outcome=PatchOutcome(status="Failed", error_code="SomeUnrecognizedError"),
        collection_started_at=datetime.now(timezone.utc),
        timeline=[
            TimelineEvent(ts=datetime.now(timezone.utc), source=Source.AZURE_CONTROL_PLANE,
                          kind="patch_install_result", summary="install failed", raw_ref="resourcegraph:install:vm-1"),
        ],
        sources_attempted=[Source.AZURE_CONTROL_PLANE, Source.GUEST_LINUX],
        sources_succeeded=[Source.AZURE_CONTROL_PLANE],
        collection_gaps=["guest_linux: Run Command timed out after 60s"],
    )


class _RecollectOnceRCAAgent:
    """Asks for more evidence on its first call, then settles once the
    orchestrator hands it the recollected (merged) bundle."""

    def __init__(self):
        self.calls = 0
        self.bundles_seen: list[EvidenceBundle] = []

    def diagnose(self, cluster, representative, near_misses=None, retrieval_context=""):
        self.calls += 1
        self.bundles_seen.append(representative)
        if self.calls == 1:
            return RCAResult(
                cluster_id=cluster.cluster_id, origin=ResultOrigin.DEEP_RCA, cause_family=CauseFamily.UNRESOLVED,
                title="Insufficient evidence", causal_chain=[], confidence=0.15,
                missing_evidence=[_DISK_LABEL],
            )
        return RCAResult(
            cluster_id=cluster.cluster_id, origin=ResultOrigin.DEEP_RCA, cause_family=CauseFamily.CAPACITY,
            title="Disk nearly full", causal_chain=[], confidence=0.3, missing_evidence=[],
        )


def test_recollected_guest_findings_are_visible_in_the_persisted_machine_detail(session_factory):
    run = PatchRun(
        run_id="run-1", maintenance_configuration_id="cfg", subscription_id="s", scope_name="test",
        started_at=datetime.now(timezone.utc), total_machines=1, trigger_mode=TriggerMode.AD_HOC,
    )
    bundle = _first_pass_bundle()

    def recollect_fn(representative, missing_evidence):
        return {
            Source.GUEST_LINUX: CollectionResult(
                events=[TimelineEvent(ts=datetime.now(timezone.utc), source=Source.GUEST_LINUX, kind="disk_usage",
                                       summary="disk nearly full", raw_ref="guest:disk:vm-1:0")],
                checks_performed=[_DISK_LABEL],
                checks_finding_counts={_DISK_LABEL: 1},
            ),
        }

    agent = _RecollectOnceRCAAgent()
    pipeline = Pipeline(session_factory=session_factory, rca_agent=agent, recollect_fn=recollect_fn)
    pipeline.run(run, [bundle])

    assert agent.calls == 2  # confirms recollection genuinely fired
    # The second diagnose() call must have seen the recollected evidence.
    assert any(ev.raw_ref == "guest:disk:vm-1:0" for ev in agent.bundles_seen[1].timeline)

    with session_factory() as session:
        detail = repository.get_machine_detail(session, "run-1", "vm-1")

    assert detail is not None
    assert detail.checks_finding_counts.get(_DISK_LABEL) == 1
    assert _DISK_LABEL in detail.checks_performed
    assert any(ev.get("raw_ref") == "guest:disk:vm-1:0" for ev in detail.timeline)
    # The stale first-pass gap must be gone - guest_linux succeeded this time.
    assert not any(g.startswith("guest_linux:") for g in detail.collection_gaps)
