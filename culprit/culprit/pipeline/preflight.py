"""Pre-flight prediction (proposal Section 10): the rule engine alone, run
against each in-scope machine's *current* state rather than a completed
run's failure outcome, to predict which machines will fail the next
maintenance window while there's still time to fix them - "the shortest
path from 'interesting analysis' to 'our failure rate went down'".

Deliberately rule-engine-only, never deep RCA: this is meant to run
continuously between cycles at essentially zero marginal cost (Section
10), which ruling out a model call from the loop is what makes true. Every
collector this reuses already reports *current* facts (today's free disk,
today's heartbeat, today's pending-reboot flag) regardless of whether a
patch has actually failed yet, so no new collection code is needed -
only a synthetic single-machine Cluster to satisfy `evaluate_rules`'s
signature (cluster_id is the only field any rule actually reads off it).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from culprit.collectors.base import Collector
from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
from culprit.models.evidence import MachineIdentity, Source
from culprit.models.preflight import PreflightFinding
from culprit.pipeline.collection import collect_all
from culprit.pipeline.rules import evaluate_rules

# Matches the proposal's own disk-trend worked example (Section 5: "T-9d
# ... rising, +3.1%/d") - long enough to see a slow-climbing precondition,
# short enough that a fresh Datadog/guest query stays cheap.
LOOKBACK_DAYS = 9


def run_preflight_scan(
    collectors: dict[Source, Collector],
    machines: list[MachineIdentity],
    scan_id: str = "preflight",
) -> list[PreflightFinding]:
    """Collects current-state evidence for every machine and returns only
    the ones a deterministic rule fires on - a machine the rules have
    nothing to say about isn't a prediction, so it's silently dropped
    rather than reported as "no problem found" (the rule engine was never
    asked whether it's healthy, only whether one of these specific
    preconditions is already present)."""
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(days=LOOKBACK_DAYS)

    bundles = collect_all(scan_id, machines, collectors, window_start, window_end)

    findings: list[PreflightFinding] = []
    for bundle in bundles:
        cluster = Cluster(
            cluster_id=f"preflight:{bundle.machine.vm_id}",
            run_id=scan_id,
            cluster_key=f"preflight:{bundle.machine.vm_id}",
            fingerprint=Fingerprint(
                error_code_normalized="preflight",
                os_family=bundle.machine.os_family,
                failing_target="",
            ),
            members=[ClusterMember(vm_id=bundle.machine.vm_id, vm_name=bundle.machine.vm_name)],
            representative_vm_id=bundle.machine.vm_id,
        )
        result = evaluate_rules(cluster, bundle)
        if result is None:
            continue
        findings.append(PreflightFinding(machine=bundle.machine, result=result, scanned_at=window_end))
    return findings
