"""Builds the exact scenario used throughout the proposal: 312 machines,
47 failed, collapsing into 6 clusters sized 19/11/8/5/3/1 (Section 6's
worked figure) with the causes named in Sections 6 and 8.

This generates realistic EvidenceBundles - not hand-typed fixtures - so
the same rule engine and clustering code that would run against real
Azure/Datadog output runs here unchanged. Nothing about the pipeline
knows or cares that these bundles came from a generator instead of a
live collection pass.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from culprit.models.evidence import EvidenceBundle, MachineIdentity, OSFamily, PatchOutcome, Source, TimelineEvent
from culprit.models.patch_run import PatchRun, TriggerMode

SUBSCRIPTION_ID = "11111111-2222-3333-4444-555555555555"
RESOURCE_GROUP = "rg-culprit-demo"
RUN_ID = "mc-run-2026-09-26-prod-linux-weekly-0400"
TOTAL_MACHINES = 312
FAILED_COUNT = 47
CLUSTER_SIZES = [19, 11, 8, 5, 3, 1]
assert sum(CLUSTER_SIZES) == FAILED_COUNT

WINDOW_START = datetime(2026, 9, 26, 4, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(hours=3)


def _machine(name: str, os_family: OSFamily, os_version: str) -> MachineIdentity:
    return MachineIdentity(
        vm_id=f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/{name}",
        vm_name=name,
        resource_group=RESOURCE_GROUP,
        subscription_id=SUBSCRIPTION_ID,
        os_family=os_family,
        os_version=os_version,
        tags={"env": "prod"},
    )


def _ev(ts: datetime, source: Source, kind: str, summary: str, detail: dict, ref: str) -> TimelineEvent:
    return TimelineEvent(ts=ts, source=source, kind=kind, summary=summary, detail=detail, raw_ref=ref)


def _boot_full_bundle(i: int) -> EvidenceBundle:
    name = f"vm-prd-app-{100 + i:04d}"
    machine = _machine(name, OSFamily.LINUX, "Ubuntu 22.04")
    outcome = PatchOutcome(
        status="Failed",
        error_code="PackageManagerFailure",
        packages_failed=[f"linux-image-5.15.0-{91+i%3}-generic"],
        started_at=WINDOW_START,
        ended_at=WINDOW_START + timedelta(minutes=18),
        window_minutes=180,
    )
    timeline = [
        _ev(WINDOW_START - timedelta(days=9), Source.DATADOG_METRIC, "metric_trend",
            "system.disk.in_use{mount:/boot} = 0.71 at T-9d (rising)",
            {"disk_low": False, "mount": "/boot", "metric": "disk_boot", "value": 0.71},
            f"datadog:metric:disk_boot:{machine.vm_id}:t9"),
        _ev(WINDOW_START - timedelta(days=2), Source.DATADOG_MONITOR, "monitor_state",
            "Monitor 'boot partition > 85%' state=Warn (no notification route configured)",
            {"monitor_id": 8842},
            f"datadog:monitor:8842:{machine.vm_id}"),
        _ev(WINDOW_START - timedelta(hours=2), Source.DATADOG_METRIC, "metric_trend",
            "system.disk.in_use{mount:/boot} = 0.99 at window open",
            {"disk_low": True, "mount": "/boot", "metric": "disk_boot", "value": 0.99},
            f"datadog:metric:disk_boot:{machine.vm_id}:t0"),
        _ev(WINDOW_START + timedelta(minutes=14), Source.GUEST_LINUX, "package_manager_log",
            "apt/history.log Error: gzip: stdout: No space left on device",
            {"write_failure": True, "disk_low": True, "mount": "/boot"},
            f"guest:apt/history.log:{machine.vm_id}:0"),
        _ev(WINDOW_START + timedelta(minutes=15), Source.GUEST_LINUX, "disk_usage",
            "/boot at 99% used, 3.2M free",
            {"disk_low": True, "mount": "/boot"},
            f"guest:df:{machine.vm_id}:0"),
        _ev(WINDOW_START + timedelta(minutes=18), Source.AZURE_CONTROL_PLANE, "patch_result",
            "patchinstallationresults -> Failed / PackageManagerFailure",
            {"normalized_error": "packagemanagerfailure"},
            f"resourcegraph:{machine.vm_id}:{RUN_ID}"),
    ]
    return EvidenceBundle(
        run_id=RUN_ID, machine=machine, outcome=outcome, timeline=timeline,
        collection_started_at=WINDOW_END, collection_completed_at=WINDOW_END,
        sources_attempted=[Source.AZURE_CONTROL_PLANE, Source.GUEST_LINUX, Source.DATADOG_METRIC, Source.DATADOG_MONITOR],
        sources_succeeded=[Source.AZURE_CONTROL_PLANE, Source.GUEST_LINUX, Source.DATADOG_METRIC, Source.DATADOG_MONITOR],
    )


def _patch_mode_bundle(i: int) -> EvidenceBundle:
    name = f"vm-prd-web-{200 + i:04d}"
    machine = _machine(name, OSFamily.LINUX, "Ubuntu 22.04")
    outcome = PatchOutcome(status="Skipped", error_code="Skipped", started_at=WINDOW_START, window_minutes=180)
    timeline = [
        _ev(WINDOW_START, Source.AZURE_CONTROL_PLANE, "patch_mode",
            "VM patchMode = AutomaticByOS (expected AutomaticByPlatform)",
            {"mode": "AutomaticByOS"},
            f"resourcegraph:patchmode:{machine.vm_id}"),
        _ev(WINDOW_START, Source.AZURE_CONTROL_PLANE, "patch_result",
            "Machine not eligible for scheduled orchestration - skipped",
            {"normalized_error": "skipped"},
            f"resourcegraph:{machine.vm_id}:{RUN_ID}"),
    ]
    return EvidenceBundle(
        run_id=RUN_ID, machine=machine, outcome=outcome, timeline=timeline,
        collection_started_at=WINDOW_END, collection_completed_at=WINDOW_END,
        sources_attempted=[Source.AZURE_CONTROL_PLANE], sources_succeeded=[Source.AZURE_CONTROL_PLANE],
    )


def _window_exceeded_bundle(i: int) -> EvidenceBundle:
    name = f"vm-prd-batch-{300 + i:04d}"
    machine = _machine(name, OSFamily.LINUX, "Ubuntu 20.04")
    outcome = PatchOutcome(
        status="Failed", error_code="MaintenanceWindowExceeded",
        packages_installed=[f"pkg-{n}" for n in range(30)],
        packages_failed=[f"pkg-{n}" for n in range(30, 45)],
        started_at=WINDOW_START, ended_at=WINDOW_START + timedelta(hours=3), window_minutes=180,
    )
    timeline = [
        _ev(WINDOW_START - timedelta(days=1), Source.AZURE_CONTROL_PLANE, "patch_result",
            "Last successful assessment: 412 pending updates (no patch cycle run in ~5 months)",
            {},
            f"resourcegraph:assessment:{machine.vm_id}"),
        _ev(WINDOW_START + timedelta(hours=3), Source.AZURE_CONTROL_PLANE, "patch_result",
            "patchinstallationresults -> Failed / MaintenanceWindowExceeded (15 packages still queued)",
            {"normalized_error": "maintenancewindowexceeded"},
            f"resourcegraph:{machine.vm_id}:{RUN_ID}"),
    ]
    return EvidenceBundle(
        run_id=RUN_ID, machine=machine, outcome=outcome, timeline=timeline,
        collection_started_at=WINDOW_END, collection_completed_at=WINDOW_END,
        sources_attempted=[Source.AZURE_CONTROL_PLANE], sources_succeeded=[Source.AZURE_CONTROL_PLANE],
    )


def _agent_unresponsive_bundle(i: int) -> EvidenceBundle:
    name = f"vm-prd-cache-{400 + i:04d}"
    machine = _machine(name, OSFamily.LINUX, "Ubuntu 22.04")
    outcome = PatchOutcome(status="Failed", error_code="ExtensionOperationFailed", started_at=WINDOW_START, window_minutes=180)
    timeline = [
        _ev(WINDOW_START, Source.AZURE_MONITOR, "heartbeat_gap",
            "No Heartbeat rows found spanning the maintenance window",
            {"agent_unresponsive": True},
            f"loganalytics:heartbeat:{machine.vm_id}"),
        _ev(WINDOW_START + timedelta(minutes=5), Source.AZURE_CONTROL_PLANE, "patch_result",
            "patchinstallationresults -> Failed / ExtensionOperationFailed",
            {"normalized_error": "extensionoperationfailed"},
            f"resourcegraph:{machine.vm_id}:{RUN_ID}"),
    ]
    return EvidenceBundle(
        run_id=RUN_ID, machine=machine, outcome=outcome, timeline=timeline,
        collection_started_at=WINDOW_END, collection_completed_at=WINDOW_END,
        sources_attempted=[Source.AZURE_CONTROL_PLANE, Source.AZURE_MONITOR],
        sources_succeeded=[Source.AZURE_CONTROL_PLANE, Source.AZURE_MONITOR],
    )


def _entitlement_expired_bundle(i: int) -> EvidenceBundle:
    name = f"vm-prd-rhel-{500 + i:04d}"
    machine = _machine(name, OSFamily.LINUX, "RHEL 8.9")
    outcome = PatchOutcome(status="Failed", error_code="PackageManagerFailure", started_at=WINDOW_START, window_minutes=180)
    timeline = [
        _ev(WINDOW_START, Source.GUEST_LINUX, "entitlement_state",
            "subscription-manager status: Overall Status: Invalid",
            {"entitlement_expired": True},
            f"guest:subman:{machine.vm_id}"),
        _ev(WINDOW_START + timedelta(minutes=3), Source.AZURE_CONTROL_PLANE, "patch_result",
            "patchinstallationresults -> Failed / PackageManagerFailure (repo access denied)",
            {"normalized_error": "packagemanagerfailure"},
            f"resourcegraph:{machine.vm_id}:{RUN_ID}"),
    ]
    return EvidenceBundle(
        run_id=RUN_ID, machine=machine, outcome=outcome, timeline=timeline,
        collection_started_at=WINDOW_END, collection_completed_at=WINDOW_END,
        sources_attempted=[Source.AZURE_CONTROL_PLANE, Source.GUEST_LINUX],
        sources_succeeded=[Source.AZURE_CONTROL_PLANE, Source.GUEST_LINUX],
    )


def _unresolved_bundle() -> EvidenceBundle:
    name = "vm-prd-legacy-0601"
    machine = _machine(name, OSFamily.WINDOWS, "Windows Server 2019")
    outcome = PatchOutcome(status="Failed", error_code="UnknownError", started_at=WINDOW_START, window_minutes=180)
    timeline = [
        _ev(WINDOW_START + timedelta(minutes=40), Source.AZURE_CONTROL_PLANE, "patch_result",
            "patchinstallationresults -> Failed / UnknownError",
            {"normalized_error": "unknownerror"},
            f"resourcegraph:{machine.vm_id}:{RUN_ID}"),
    ]
    return EvidenceBundle(
        run_id=RUN_ID, machine=machine, outcome=outcome, timeline=timeline,
        collection_started_at=WINDOW_END, collection_completed_at=WINDOW_END,
        sources_attempted=[Source.AZURE_CONTROL_PLANE, Source.GUEST_WINDOWS, Source.AZURE_MONITOR],
        sources_succeeded=[Source.AZURE_CONTROL_PLANE],
        collection_gaps=[
            "guest_windows: Run Command timed out after 60s (WinRM unreachable)",
            "azure_monitor: workspace query returned no rows for this Computer name",
        ],
    )


def build_scenario() -> tuple[PatchRun, list[EvidenceBundle]]:
    run = PatchRun(
        run_id=RUN_ID,
        maintenance_configuration_id=f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Maintenance/maintenanceConfigurations/prod-linux-weekly",
        subscription_id=SUBSCRIPTION_ID,
        scope_name="prod-linux-weekly",
        started_at=WINDOW_START,
        ended_at=WINDOW_END,
        total_machines=TOTAL_MACHINES,
        trigger_mode=TriggerMode.SCHEDULED,
    )

    bundles: list[EvidenceBundle] = []
    bundles += [_boot_full_bundle(i) for i in range(CLUSTER_SIZES[0])]
    bundles += [_patch_mode_bundle(i) for i in range(CLUSTER_SIZES[1])]
    bundles += [_window_exceeded_bundle(i) for i in range(CLUSTER_SIZES[2])]
    bundles += [_agent_unresponsive_bundle(i) for i in range(CLUSTER_SIZES[3])]
    bundles += [_entitlement_expired_bundle(i) for i in range(CLUSTER_SIZES[4])]
    bundles += [_unresolved_bundle()]

    assert len(bundles) == FAILED_COUNT
    return run, bundles
