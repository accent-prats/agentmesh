"""Fingerprinting and clustering models (proposal Section 6 - "cluster
before you diagnose"). This is the load-bearing design decision: expensive
reasoning runs once per Fingerprint, not once per failed machine.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from culprit.models.evidence import OSFamily


class Fingerprint(BaseModel):
    """A deterministic signature computed from cheap, structural evidence -
    never from free-text log content, which is what would make two
    unrelated failures collide or one real failure split into noise.

    Equality/hashing is defined purely by these fields; `fingerprint_id`
    (see fingerprint.py) is the stable hash used as the cluster key.
    """

    error_code_normalized: str
    os_family: OSFamily
    failing_target: str = Field(
        ..., description="Normalized package name, KB id, or extension name that failed - "
        "'' if the failure has no single failing target (e.g. window exhaustion)"
    )
    extension_state: str = Field(default="unknown")
    precondition_signature: str = Field(
        default="",
        description="A short, sorted token list of preconditions that were true at run time "
        "(e.g. 'disk_low:/boot', 'pending_reboot', 'agent_stale') - part of the fingerprint "
        "because the same error code with different preconditions is usually a different cause.",
    )

    def key(self) -> tuple:
        return (
            self.error_code_normalized,
            self.os_family.value,
            self.failing_target,
            self.extension_state,
            self.precondition_signature,
        )


class ClusterMember(BaseModel):
    vm_id: str
    vm_name: str
    # Added for remediation execution (culprit/remediation/) - Run Command
    # needs (resource_group, vm_name, subscription_id) to target a real VM,
    # and a cluster's own members are the only persisted record of "which
    # machines" past the run that collected them (the richer, transient
    # MachineIdentity is discarded once the run completes). Not os_family -
    # every member of a cluster already shares one via Fingerprint.os_family,
    # by construction (clustering groups on fingerprint equality). Blank on
    # any cluster persisted before this field existed - handled as a
    # per-machine remediation failure, not a crash.
    resource_group: str = ""
    subscription_id: str = ""
    deviation_notes: list[str] = Field(
        default_factory=list,
        description="Ways this machine's evidence differs from the cluster's representative "
        "member - surfaced in the per-machine report per proposal Section 8.",
    )


class Cluster(BaseModel):
    """A group of machines that failed for what the fingerprint says is the
    same reason, in one run. Clusters additionally carry a `cluster_key`
    that is stable *across* runs (derived from the fingerprint alone, not
    the run id), which is how Culprit detects a repeat offender."""

    cluster_id: str
    run_id: str
    cluster_key: str = Field(..., description="Stable hash of the Fingerprint - identical across runs")
    fingerprint: Fingerprint
    members: list[ClusterMember]
    representative_vm_id: str = Field(
        ..., description="The member whose evidence bundle is used as the canonical example "
        "when building the RCA prompt"
    )

    @property
    def size(self) -> int:
        return len(self.members)
