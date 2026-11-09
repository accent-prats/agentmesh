"""JSON (de)serializers for the handful of pipeline types that cross a
Durable Functions activity boundary - activity inputs/outputs must be
plain JSON-serializable data, never a live object (a Pydantic model
instance, a dataclass, a DB session, an Azure SDK credential).

Every Pydantic model here (EvidenceBundle, Cluster, RCAResult, PatchRun,
MachineIdentity) already supports this losslessly via `.model_dump(mode=
"json")` / `Model.model_validate(d)` - no new logic, just a single
consistent call site so every activity in activities.py spells it the
same way. `CollectionResult` is the one plain `@dataclass` in the set
(culprit/collectors/base.py) and needs an explicit (de)serializer since
dataclasses have no built-in JSON mode.
"""
from __future__ import annotations

from culprit.collectors.base import CollectionResult
from culprit.models.cluster import Cluster
from culprit.models.evidence import EvidenceBundle, MachineIdentity, PatchOutcome, TimelineEvent
from culprit.models.patch_run import PatchRun
from culprit.models.rca import RCAResult


def model_to_dict(model) -> dict:
    return model.model_dump(mode="json")


def bundle_to_dict(bundle: EvidenceBundle) -> dict:
    return model_to_dict(bundle)


def bundle_from_dict(data: dict) -> EvidenceBundle:
    return EvidenceBundle.model_validate(data)


def machine_to_dict(machine: MachineIdentity) -> dict:
    return model_to_dict(machine)


def machine_from_dict(data: dict) -> MachineIdentity:
    return MachineIdentity.model_validate(data)


def cluster_to_dict(cluster: Cluster) -> dict:
    return model_to_dict(cluster)


def cluster_from_dict(data: dict) -> Cluster:
    return Cluster.model_validate(data)


def rca_result_to_dict(result: RCAResult) -> dict:
    return model_to_dict(result)


def rca_result_from_dict(data: dict) -> RCAResult:
    return RCAResult.model_validate(data)


def patch_run_to_dict(run: PatchRun) -> dict:
    return model_to_dict(run)


def patch_run_from_dict(data: dict) -> PatchRun:
    return PatchRun.model_validate(data)


def collection_result_to_dict(result: CollectionResult) -> dict:
    return {
        "events": [model_to_dict(e) for e in result.events],
        "outcome": model_to_dict(result.outcome) if result.outcome is not None else None,
        "error": result.error,
        "patch_extension_status": result.patch_extension_status,
        "checks_performed": result.checks_performed,
        "checks_unavailable": result.checks_unavailable,
        "checks_finding_counts": result.checks_finding_counts,
    }


def collection_result_from_dict(data: dict) -> CollectionResult:
    return CollectionResult(
        events=[TimelineEvent.model_validate(e) for e in data["events"]],
        outcome=PatchOutcome.model_validate(data["outcome"]) if data.get("outcome") is not None else None,
        error=data.get("error"),
        patch_extension_status=data.get("patch_extension_status", []),
        checks_performed=data.get("checks_performed", []),
        checks_unavailable=data.get("checks_unavailable", []),
        checks_finding_counts=data.get("checks_finding_counts", {}),
    )
