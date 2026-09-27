"""Seed vendor documentation snippets for the retrieval store.

Phase 0 (proposal Section 13) replaces/extends this with documentation
relevant to the estate's actual images and vendor mix; this seed set
covers the failure taxonomy's most common families so the retrieval store
is non-empty and useful from the first run.
"""
from __future__ import annotations

from culprit.retrieval.store import Document, RetrievalStore

_SEED_DOCS = [
    Document(
        doc_id="vendor:ubuntu-boot-partition",
        title="Ubuntu: /boot partition fills up from retained kernels",
        body=(
            "Ubuntu/Debian unattended-upgrades installs new kernel packages but does not remove "
            "old ones by default. /boot is commonly sized at 512MB-1GB, which holds only 3-5 "
            "kernel versions. When it fills, update-initramfs fails mid-write with 'No space left "
            "on device' and dpkg aborts the transaction. Fix: purge old kernel packages "
            "(apt autoremove --purge, keeping the running kernel and one fallback), then complete "
            "the interrupted transaction with dpkg --configure -a. Prevent recurrence with a "
            "kernel-retention policy (e.g. unattended-upgrades::Remove-Unused-Kernel-Packages)."
        ),
        kind="vendor_doc",
        tags=["capacity", "boot", "kernel", "dpkg", "ubuntu", "debian"],
    ),
    Document(
        doc_id="vendor:azure-patch-orchestration-modes",
        title="Azure Update Manager: patchMode must be AutomaticByPlatform for scheduled runs",
        body=(
            "A VM's patchMode setting (ImageDefault, AutomaticByOS, or AutomaticByPlatform) "
            "controls whether Azure Update Manager can orchestrate patching via a maintenance "
            "configuration. Only AutomaticByPlatform machines are eligible for scheduled runs; "
            "others are skipped or fail assessment. bypassPlatformSafetyChecksOnUserSchedule must "
            "also be true when patchMode is AutomaticByPlatform and a custom schedule is used."
        ),
        kind="vendor_doc",
        tags=["configuration", "patchmode", "azure", "orchestration"],
    ),
    Document(
        doc_id="vendor:windows-update-error-codes",
        title="Windows Update common error codes",
        body=(
            "0x80070070: ERROR_DISK_FULL - insufficient disk space for the update payload or "
            "staging. 0x8024401C / 0x80244022: WU client could not reach the update source "
            "(WSUS or Windows Update servers) - check network path, proxy, and WSUS server "
            "health. 0x8007000E: E_OUTOFMEMORY - insufficient memory during update processing. "
            "0x80070005: E_ACCESSDENIED - a permission or policy is blocking the operation."
        ),
        kind="vendor_doc",
        tags=["windows", "wu", "error_code", "configuration"],
    ),
    Document(
        doc_id="vendor:dpkg-lock-recovery",
        title="Debian/Ubuntu: recovering from a held dpkg lock",
        body=(
            "/var/lib/dpkg/lock-frontend is held by whichever process is currently running a "
            "package operation. If unattended-upgrades and a manual apt run (or a config-"
            "management agent) overlap, the second one fails immediately. Identify the holder "
            "with 'fuser /var/lib/dpkg/lock-frontend' or 'lslocks', confirm it is safe to "
            "interrupt, then run 'dpkg --configure -a' to complete any partial transaction before "
            "retrying. Prevent recurrence by staggering config-management runs away from the "
            "patch window."
        ),
        kind="vendor_doc",
        tags=["package_manager_state", "dpkg", "lock", "linux"],
    ),
    Document(
        doc_id="vendor:rhel-subscription-entitlement",
        title="RHEL: subscription-manager entitlement lapses block repository access",
        body=(
            "'subscription-manager status' returns 'Overall Status: Invalid' or 'Unknown' when "
            "an entitlement has expired or was never attached. This blocks access to RHEL "
            "repositories entirely - yum/dnf will fail with repository errors that look like a "
            "network problem but are actually an entitlement problem. Renew or re-attach the "
            "subscription, then retry."
        ),
        kind="vendor_doc",
        tags=["source_entitlement", "rhel", "subscription-manager"],
    ),
    Document(
        doc_id="vendor:post-patch-service-regression",
        title="A successful patch can still break a service on reboot",
        body=(
            "Azure Update Manager reports success once the OS-level patch install and reboot "
            "complete - it does not verify that application services came back healthy. A "
            "common regression: a config file or systemd unit gets reset or a dependency version "
            "shifts, and the service fails to start post-reboot. This is only visible from "
            "application-level monitoring (e.g. Datadog service checks / process checks) in the "
            "hour after the reboot, not from the Azure patch result."
        ),
        kind="vendor_doc",
        tags=["post_patch_regression", "reboot", "datadog"],
    ),
]


def default_retrieval_store() -> RetrievalStore:
    return RetrievalStore(documents=list(_SEED_DOCS))
