"""Azure control-plane collector: Resource Graph (patch outcomes) + Activity
Log (control-plane changes in the blast window).

Requires (proposal Section 12, security posture):
  - An Entra ID workload identity (a plain `DefaultAzureCredential` picks up
    a managed identity in production, or `az login` locally) with:
      * Reader on the subscription/resource group
      * The custom 'Culprit Reader' role for Resource Graph + Activity Log
        (see culprit/security/rbac/culprit-reader-role.json)
  - `azure-identity`, `azure-mgmt-resourcegraph`, `azure-mgmt-monitor`

This module is read-only by construction: every client call below is a
`list`/`resources` query. There is no code path here that can write to a
subscription, which is what makes the RBAC role's read-only scope an
enforceable guarantee rather than a policy on paper.
"""
from __future__ import annotations

from datetime import datetime, timezone

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector
from culprit.models.evidence import AzureApiErrorDetail, PatchOutcome, Source, TimelineEvent

try:  # pragma: no cover - exercised only when the optional Azure SDKs are installed
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest

    _AZURE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _AZURE_SDK_AVAILABLE = False


# Real Resource Graph table/column shapes exposed by Azure Update Manager.
# `patchinstallationresources` carries per-run, per-machine install results;
# `patchassessmentresources` carries the last assessment (pending patch
# counts); `maintenanceresources` carries the maintenance run itself.
_INSTALL_RESULT_QUERY = """
patchinstallationresources
| where type =~ 'microsoft.compute/virtualmachines/patchinstallationresults'
| where id startswith '{vm_id}'
| where properties.startDateTime >= datetime('{window_start}')
| where properties.startDateTime <= datetime('{window_end}')
| project id, properties
| order by tostring(properties.startDateTime) desc
| limit 1
"""
# `properties` is Resource Graph's dynamic-typed column, so a bare
# `order by properties.startDateTime` fails every real invocation with
# "(InvalidQuery) ... order operator: key can't be of dynamic type" -
# `where`/comparison operators tolerate a dynamic operand, `order by`'s
# sort key does not. That exception was being caught by collect()'s own
# blanket except below and silently degrading every real machine's
# PatchOutcome to normalize.py's generic "Unknown" placeholder - found
# live, reported as "status is coming as unknown" on a real tenant run.
# Cast to a string, not datetime() - discovery.py's own
# _ALL_PATCH_RESULTS_QUERY already relies on the same fact (ISO-8601
# string lexical ordering matches chronological ordering) for its
# `arg_max`, so this matches an already-proven pattern rather than
# introducing a second cast convention.


class AzureControlPlaneCollector(Collector):
    source_name = "azure_control_plane"

    def __init__(self, subscription_id: str | None = None, credential=None):
        self.subscription_id = subscription_id
        # A pre-built credential (typically from culprit.collectors.azure_auth.build_credential,
        # fed by whatever's saved on the /culprit/settings screen) takes
        # priority; falling back to DefaultAzureCredential keeps the demo
        # and any caller that doesn't pass one working unchanged.
        self._credential = credential
        self._graph_client = None
        self._monitor_client = None

    def _ensure_clients(self, subscription_id: str) -> None:
        if not _AZURE_SDK_AVAILABLE:
            raise RuntimeError(
                "azure-identity / azure-mgmt-resourcegraph / azure-mgmt-monitor are not installed. "
                "pip install them, or use collectors.demo.DemoAzureControlPlaneCollector for offline runs."
            )
        if self._credential is None:
            self._credential = DefaultAzureCredential()
        if self._graph_client is None:
            self._graph_client = ResourceGraphClient(self._credential)
        if self._monitor_client is None:
            self._monitor_client = MonitorManagementClient(self._credential, subscription_id)

    def collect(self, request: CollectionRequest) -> CollectionResult:
        self._ensure_clients(request.machine.subscription_id)
        events: list[TimelineEvent] = []
        outcome: PatchOutcome | None = None
        error = None

        try:
            from culprit.security.kql import escape_kql_string

            query = _INSTALL_RESULT_QUERY.format(
                vm_id=escape_kql_string(request.machine.vm_id),
                window_start=request.window_start.isoformat(),
                window_end=request.window_end.isoformat(),
            )
            result = self._graph_client.resources(
                QueryRequest(subscriptions=[request.machine.subscription_id], query=query)
            )
            rows = result.data or []
            if rows:
                props = rows[0]["properties"]
                outcome = _outcome_from_install_result(props)
                events.append(
                    TimelineEvent(
                        ts=_parse_ts(props.get("lastModifiedDateTime") or props.get("startDateTime")),
                        source=Source.AZURE_CONTROL_PLANE,
                        kind="patch_result",
                        summary=f"patchinstallationresults -> {props.get('status')} / {props.get('errorCode') or ''}".strip(),
                        detail={"normalized_error": (props.get("errorCode") or "").lower()},
                        raw_ref=f"resourcegraph:{rows[0]['id']}",
                    )
                )
                # One event per Azure-reported error detail - the same
                # `ApiError.details[]` entries a separate internal report
                # was found pulling from this exact Resource Graph field
                # (2026-10-15) to show messages like "There is no enough
                # time left to continue applying the next update" that
                # Culprit's own RCA had no visibility into. Reaches the
                # model for free via render_timeline_text() - no prompt
                # change needed, same as patch_extension_status.py.
                for i, detail in enumerate(outcome.error_details):
                    events.append(
                        TimelineEvent(
                            ts=_parse_ts(props.get("lastModifiedDateTime") or props.get("startDateTime")),
                            source=Source.AZURE_CONTROL_PLANE,
                            kind="azure_patch_error",
                            summary=(f"Azure-reported install error: {detail.message or detail.code or '(no message)'}")[:240],
                            detail={"code": detail.code, "target": detail.target},
                            raw_ref=f"resourcegraph:{rows[0]['id']}:error:{i}",
                        )
                    )
        except Exception as exc:  # noqa: BLE001 - collection must degrade, not crash the pipeline
            error = f"Resource Graph query failed: {exc}"

        try:
            events.extend(self._activity_log_events(request))
        except Exception as exc:  # noqa: BLE001
            error = (error + "; " if error else "") + f"Activity Log query failed: {exc}"

        return CollectionResult(events=events, outcome=outcome, error=error)

    def _activity_log_events(self, request: CollectionRequest) -> list[TimelineEvent]:
        from culprit.security.kql import escape_kql_string

        filter_str = (
            f"eventTimestamp ge '{request.window_start.isoformat()}' "
            f"and eventTimestamp le '{request.window_end.isoformat()}' "
            f"and resourceUri eq '{escape_kql_string(request.machine.vm_id)}'"
        )
        events: list[TimelineEvent] = []
        for entry in self._monitor_client.activity_logs.list(filter=filter_str):
            events.append(
                TimelineEvent(
                    ts=entry.event_timestamp or datetime.now(timezone.utc),
                    source=Source.AZURE_CONTROL_PLANE,
                    kind="activity_log",
                    summary=f"{entry.operation_name.localized_value if entry.operation_name else 'operation'} "
                    f"by {entry.caller or 'unknown'} -> {entry.status.value if entry.status else ''}",
                    detail={
                        "nsg_change": bool(entry.operation_name and "networkSecurityGroups" in (entry.operation_name.value or "")),
                        "policy_block": bool(entry.operation_name and "policy" in (entry.operation_name.value or "").lower() and entry.status and entry.status.value == "Failed"),
                    },
                    raw_ref=f"activitylog:{entry.event_data_id or entry.correlation_id}",
                )
            )
        return events


def _parse_error_details(details: object) -> list[AzureApiErrorDetail]:
    """Defensive by construction, never raises - found 2026-10-15: the
    previous code assigned this array straight to a `str | None` field,
    which raised a Pydantic ValidationError on any machine where Azure
    actually populated it, and that exception was swallowed by collect()'s
    blanket except - silently discarding the *entire* PatchOutcome and its
    TimelineEvent for that machine, not just this one field. A malformed
    entry here must degrade to being skipped, not repeat that failure."""
    if not isinstance(details, list):
        return []
    return [
        AzureApiErrorDetail(code=d.get("code"), message=d.get("message"), target=d.get("target"))
        for d in details if isinstance(d, dict)
    ]


def _outcome_from_install_result(props: dict) -> PatchOutcome:
    error = props.get("error") if isinstance(props.get("error"), dict) else {}
    return PatchOutcome(
        status=props.get("status", "Unknown"),
        error_code=props.get("errorCode"),
        error_message=error.get("message"),
        error_details=_parse_error_details(error.get("details")),
        packages_failed=[p["patchName"] for p in props.get("patches", []) if p.get("state") == "Failed"] if props.get("patches") else [],
        packages_installed=[p["patchName"] for p in props.get("patches", []) if p.get("state") == "Installed"] if props.get("patches") else [],
        kbs_failed=[p["kbId"] for p in props.get("patches", []) if p.get("state") == "Failed" and p.get("kbId")] if props.get("patches") else [],
        reboot_status=props.get("rebootStatus"),
        started_at=_parse_ts(props.get("startDateTime")),
        ended_at=_parse_ts(props.get("lastModifiedDateTime")),
        window_minutes=props.get("maximumDuration"),
    )


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
