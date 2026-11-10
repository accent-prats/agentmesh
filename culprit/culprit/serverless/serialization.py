"""JSON (de)serializers for the handful of pipeline types that cross a
Durable Functions activity boundary - activity inputs/outputs must be
plain JSON-serializable data, never a live object (a Pydantic model
instance, a dataclass, a DB session, an Azure SDK credential).

Every Pydantic model here (EvidenceBundle, Cluster, RCAResult, PatchRun,
MachineIdentity) already supports this losslessly via `.model_dump(mode=
"json")` / `Model.model_validate(d)` - no new logic, just a single
consistent call site so every activity in activities.py spells it the
same way.

`CollectionResult` (culprit/collectors/base.py) never actually crosses an
activity boundary as its own type - `recollect_activity` merges it into
the representative's `EvidenceBundle` (via `normalize.merge_recollection`)
before returning, so no `CollectionResult` (de)serializer is needed here;
an earlier version of this module included one anyway, tested but with
zero real callers - removed in review 2026-11-10.
"""
from __future__ import annotations

from culprit.models.cluster import Cluster
from culprit.models.evidence import EvidenceBundle, MachineIdentity
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
