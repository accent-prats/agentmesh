"""Phase 2 remediation execution - the one route family in this app that
can mutate a customer's real Azure VM. See culprit/remediation/ for the
actual Run Command invocation and SECURITY.md's "Remediation execution"
section for the full guarantee this enforces.

Every check below runs on every single request, in this order, fresh -
nothing here is cached or trusted from an earlier check, because this
route mutates real infrastructure and a stale "it was fine a minute ago"
is unacceptable for that.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from culprit.api import deps
from culprit.config import settings
from culprit.models.remediation import (
    SUPPORTED_ACTIONS,
    RemediationActionRequest,
    RemediationExecutionResponse,
    RemediationLogEntry,
    RemediationMachineResult,
    RemediationStatus,
)

router = APIRouter(prefix="/remediation", tags=["remediation"])


@router.post("/runs/{run_id}/clusters/{cluster_id}/execute", response_model=RemediationExecutionResponse)
def execute_remediation(run_id: str, cluster_id: str, body: RemediationActionRequest) -> RemediationExecutionResponse:
    # Function-local re-import, not the module-level `from culprit.config
    # import settings` above - see routes_runs.py::trigger_demo_run's own
    # comment on why: tests replace the whole config.settings object, and
    # a stale name-bound import wouldn't see the swap. 404, not 403 - a
    # deployment with this off shouldn't reveal the route exists at all.
    from culprit import config as config_module

    if not config_module.settings.remediation_enabled:
        raise HTTPException(status_code=404)

    from culprit.db import repository
    from culprit.models.verdict import compute_family_precision

    with deps.get_session_factory()() as session:
        found = repository.get_cluster_with_result(session, run_id, cluster_id)
        if found is None:
            raise HTTPException(status_code=404, detail=f"Cluster {cluster_id} not found in run {run_id}")
        cluster, result = found

        if result.remediation is None or not result.remediation.phase2_candidate:
            raise HTTPException(status_code=409, detail={"reason": "not_phase2_candidate"})

        by_family = compute_family_precision(repository.all_verdicts(session))
        family_precision = by_family.get(result.cause_family)
        if family_precision is None or not family_precision.meets_promotion_bar(
            settings.promotion_precision_threshold, settings.promotion_min_sample
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "promotion_bar_not_met",
                    "sample_size": family_precision.sample_size if family_precision else 0,
                    "min_sample": settings.promotion_min_sample,
                    "precision": round(family_precision.precision, 4) if family_precision else 0.0,
                    "threshold": settings.promotion_precision_threshold,
                },
            )

        if SUPPORTED_ACTIONS.get(result.cause_family) != body.action_type:
            raise HTTPException(status_code=409, detail={"reason": "action_type_not_supported_for_cause_family"})

        member_by_vm_id = {m.vm_id: m for m in cluster.members}
        if body.vm_ids is None:
            targets = list(cluster.members)
        else:
            unknown = [vm_id for vm_id in body.vm_ids if vm_id not in member_by_vm_id]
            if unknown:
                raise HTTPException(status_code=400, detail=f"vm_ids not in this cluster: {unknown}")
            targets = [member_by_vm_id[vm_id] for vm_id in body.vm_ids]

        mount = result.remediation.automation_params.get("mount", "/")

    # Imported here, not up near the other early imports - every
    # not-eligible rejection above (flag off, not found, not a phase2
    # candidate, gate not met, wrong action type, unknown vm_id) must
    # still return its own clean 404/409/400 even if this module has a
    # problem, rather than every single call to this route failing with
    # the same crash regardless of input.
    from culprit.remediation.runner import RemediationRunner

    runner = RemediationRunner()
    results: list[RemediationMachineResult] = []
    for member in targets:
        if not member.resource_group or not member.subscription_id:
            outcome = {
                "status": "failed",
                "message": "This machine has no resource_group/subscription_id recorded "
                "(diagnosed before remediation targeting was added) - cannot target Run Command.",
                "free_bytes_after": None,
            }
        else:
            outcome = runner.run_disk_cleanup(
                member.subscription_id, member.resource_group, member.vm_name,
                cluster.fingerprint.os_family, mount,
            )
        results.append(RemediationMachineResult(
            vm_id=member.vm_id, vm_name=member.vm_name,
            status=RemediationStatus(outcome["status"]), message=outcome["message"],
            free_bytes_after=outcome.get("free_bytes_after"),
        ))

    executed_at = datetime.now(timezone.utc)
    with deps.get_session_factory()() as session:
        for machine_result in results:
            repository.save_remediation_action(
                session, run_id=run_id, cluster_id=cluster_id, cause_family=result.cause_family,
                action_type=body.action_type, requested_by=body.requested_by,
                requested_at=executed_at, result=machine_result,
            )

    succeeded = sum(1 for r in results if r.status == RemediationStatus.SUCCESS)
    return RemediationExecutionResponse(
        run_id=run_id, cluster_id=cluster_id, action_type=body.action_type,
        requested_by=body.requested_by, executed_at=executed_at, results=results,
        succeeded_count=succeeded, failed_count=len(results) - succeeded,
    )


@router.get("/log", response_model=list[RemediationLogEntry])
def get_remediation_log() -> list[RemediationLogEntry]:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.list_remediation_actions(session)


@router.get("/log.html")
def get_remediation_log_html():
    from fastapi.responses import HTMLResponse

    from culprit.db import repository
    from culprit.reporting.render import render_remediation_log_html

    with deps.get_session_factory()() as session:
        records = repository.list_remediation_actions(session)
    return HTMLResponse(render_remediation_log_html(records))
