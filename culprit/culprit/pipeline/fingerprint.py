"""Deterministic fingerprinting and clustering (proposal Section 6).

No model is involved anywhere in this file. That's deliberate: the
fingerprint has to be reproducible, cheap, and immune to an LLM's mood -
it's the thing that turns "47 failed machines" into "6 things are wrong"
*before* any expensive reasoning happens, and the whole cost/readability
argument in the proposal depends on that collapse being trustworthy.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
from culprit.models.evidence import EvidenceBundle, OSFamily, Source

# Normalizes vendor/OS-specific error strings down to a small stable
# vocabulary. Extend this table as new error shapes are seen in Phase 0 -
# it is intentionally a plain lookup, not a model call, because a wrong
# entry here is a one-line fix instead of a prompt-engineering exercise.
_ERROR_CODE_ALIASES: dict[str, str] = {
    # Windows Update Agent
    "0x80070070": "disk_space",
    "0x8007000e": "out_of_memory",
    "0x8024401c": "source_timeout",
    "0x80244022": "source_unavailable",
    "0x80070005": "access_denied",
    # Azure Update Manager / patch extension outcomes
    "packagemanagerfailure": "package_manager_failure",
    "maintenancewindowexceeded": "window_exceeded",
    "unknownerror": "unknown_error",
    "extensionoperationfailed": "extension_failure",
    "vmnotfound": "vm_unavailable",
}

_PRECONDITION_ORDER = [
    # Fixed order so the precondition signature is stable regardless of the
    # order collectors happened to append tokens in.
    "disk_low",
    "pending_reboot",
    "agent_stale",
    "agent_unresponsive",
    "lock_held",
    "repo_unreachable",
    "entitlement_expired",
    "nsg_change",
    "policy_block",
    "power_off",
]


def normalize_error_code(raw: str | None) -> str:
    if not raw:
        return "no_error_code"
    key = raw.strip().lower()
    return _ERROR_CODE_ALIASES.get(key, re.sub(r"[^a-z0-9_]+", "_", key))


def normalize_failing_target(bundle: EvidenceBundle) -> str:
    """Pick the single most informative failing target, or '' if the
    failure has no natural single target (e.g. a window-exhaustion case
    with many packages still queued)."""
    outcome = bundle.outcome
    if outcome.packages_failed:
        # Strip version-shaped segments - "linux-image-5.15.0-91-generic"
        # and "linux-image-5.15.0-92-generic" are the same *kind* of
        # failure and must fingerprint identically. Drop any '-'-separated
        # segment that contains a digit rather than only stripping a
        # trailing version, since the version sits in the middle here
        # (".../91/generic", not ".../generic/91").
        first = outcome.packages_failed[0]
        segments = [s for s in re.split(r"[-_]", first) if not any(ch.isdigit() for ch in s)]
        normalized = "-".join(segments)
        return normalized or first
    if outcome.kbs_failed:
        # KB ids are the identifying token itself (not a version suffix on
        # a package name) - keep them whole.
        return outcome.kbs_failed[0]
    return ""


def compute_precondition_signature(bundle: EvidenceBundle) -> str:
    tokens: set[str] = set()
    for ev in bundle.timeline:
        d = ev.detail or {}
        if d.get("disk_low"):
            mount = d.get("mount", "")
            tokens.add(f"disk_low:{mount}" if mount else "disk_low")
        if d.get("pending_reboot"):
            tokens.add("pending_reboot")
        if d.get("agent_stale"):
            tokens.add("agent_stale")
        if d.get("agent_unresponsive"):
            tokens.add("agent_unresponsive")
        if d.get("lock_held"):
            tokens.add("lock_held")
        if d.get("repo_unreachable"):
            tokens.add("repo_unreachable")
        if d.get("entitlement_expired"):
            tokens.add("entitlement_expired")
        if d.get("nsg_change"):
            tokens.add("nsg_change")
        if d.get("policy_block"):
            tokens.add("policy_block")
        if d.get("power_off"):
            tokens.add("power_off")

    ordered = [t for t in _PRECONDITION_ORDER if any(tok == t or tok.startswith(t + ":") for tok in tokens)]
    # Re-attach the ':mount'-style suffix tokens in their original form.
    rendered = []
    for prefix in ordered:
        match = next((tok for tok in tokens if tok == prefix or tok.startswith(prefix + ":")), prefix)
        rendered.append(match)
    return ",".join(rendered)


def build_fingerprint(bundle: EvidenceBundle) -> Fingerprint:
    return Fingerprint(
        error_code_normalized=normalize_error_code(bundle.outcome.error_code),
        os_family=bundle.machine.os_family,
        failing_target=normalize_failing_target(bundle),
        extension_state=_extension_state(bundle),
        precondition_signature=compute_precondition_signature(bundle),
    )


def _extension_state(bundle: EvidenceBundle) -> str:
    for ev in bundle.events_from(Source.AZURE_CONTROL_PLANE):
        if ev.kind == "extension_provisioning" and ev.detail.get("state"):
            return str(ev.detail["state"])
    return "unknown"


def fingerprint_id(fp: Fingerprint) -> str:
    """Stable across runs - this is the `cluster_key` that lets Culprit say
    'this is the third cycle running' for the same underlying cause."""
    raw = "|".join(str(part) for part in fp.key())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def cluster_run(run_id: str, bundles: list[EvidenceBundle]) -> list[Cluster]:
    """Group every failed machine in a run by fingerprint.

    Only machines whose outcome is not a success are clustered - callers
    are expected to have already filtered `bundles` to failures, but this
    function is defensive about it since feeding a mixed list is an easy
    caller mistake.
    """
    groups: dict[str, list[EvidenceBundle]] = defaultdict(list)
    fingerprints: dict[str, Fingerprint] = {}

    for bundle in bundles:
        if bundle.outcome.status.lower() in ("succeeded",):
            continue
        fp = build_fingerprint(bundle)
        key = fingerprint_id(fp)
        groups[key].append(bundle)
        fingerprints[key] = fp

    clusters: list[Cluster] = []
    for key, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        fp = fingerprints[key]
        member_models = [
            ClusterMember(
                vm_id=b.machine.vm_id,
                vm_name=b.machine.vm_name,
                resource_group=b.machine.resource_group,
                subscription_id=b.machine.subscription_id,
                deviation_notes=_deviation_notes(b, members[0]),
            )
            for b in members
        ]
        clusters.append(
            Cluster(
                cluster_id=f"{run_id}:{key}",
                run_id=run_id,
                cluster_key=key,
                fingerprint=fp,
                members=member_models,
                representative_vm_id=members[0].machine.vm_id,
            )
        )
    return clusters


def _deviation_notes(member: EvidenceBundle, representative: EvidenceBundle) -> list[str]:
    """Cheap, structural diff used for the per-machine report (proposal
    Section 8) - not a full evidence diff, just the handful of fields most
    likely to matter to an engineer scanning the cluster's member list."""
    if member.machine.vm_id == representative.machine.vm_id:
        return []
    notes = []
    if member.outcome.window_minutes != representative.outcome.window_minutes:
        notes.append(
            f"window {member.outcome.window_minutes}m vs representative "
            f"{representative.outcome.window_minutes}m"
        )
    if member.machine.os_version != representative.machine.os_version:
        notes.append(f"OS version {member.machine.os_version} vs {representative.machine.os_version}")
    return notes
