"""Azure Monitor / Log Analytics collector: Heartbeat gaps, Event (Windows)
and Syslog (Linux) around the maintenance window.

Requires `azure-monitor-query` + `azure-identity`, and a Log Analytics
Reader role scoped to the workspace (see culprit/security/rbac). The
workspace id is per-subscription/environment configuration, not hardcoded
here - pass it via `CULPRIT_LOG_ANALYTICS_WORKSPACE_ID` or the constructor.
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector, non_guest_finding_counts
from culprit.models.evidence import OSFamily, Source, TimelineEvent
from culprit.observability import safe_exc_summary

log = logging.getLogger(__name__)

try:  # pragma: no cover
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient, LogsQueryStatus

    _MONITOR_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _MONITOR_SDK_AVAILABLE = False


# Heartbeat gap detection: a machine reporting fine before the window and
# silent during it is itself evidence (see rule_agent_not_ready) - this is
# why an absent Datadog agent or absent Heartbeat row is treated as a
# first-class signal rather than "no data".
_HEARTBEAT_QUERY = """
Heartbeat
| where Computer == '{computer}' or ResourceId =~ '{vm_id}'
| where TimeGenerated between (datetime('{gap_check_start}') .. datetime('{window_end}'))
| summarize LastBeat = max(TimeGenerated)
"""

_WINDOWS_EVENT_QUERY = """
Event
| where Computer == '{computer}'
| where TimeGenerated between (datetime('{window_start}') .. datetime('{window_end}'))
| where EventLevelName in ('Error', 'Warning')
| where Source has 'WindowsUpdateClient' or Source has 'Microsoft-Windows-Servicing'
| project TimeGenerated, EventID, RenderedDescription, Source
| order by TimeGenerated asc
"""

_LINUX_SYSLOG_QUERY = """
Syslog
| where Computer == '{computer}'
| where TimeGenerated between (datetime('{window_start}') .. datetime('{window_end}'))
| where ProcessName in ('dpkg', 'apt', 'yum', 'dnf', 'unattended-upgrades')
| project TimeGenerated, ProcessName, SyslogMessage, SeverityLevel
| order by TimeGenerated asc
"""


class AzureMonitorCollector(Collector):
    source_name = "azure_monitor"

    def __init__(self, workspace_id: str, credential=None):
        self.workspace_id = workspace_id
        self._credential = credential
        self._client = None

    def _ensure_client(self) -> None:
        if not _MONITOR_SDK_AVAILABLE:
            raise RuntimeError(
                "azure-monitor-query / azure-identity are not installed. "
                "pip install them, or use the demo collector for offline runs."
            )
        if self._credential is None:
            self._credential = DefaultAzureCredential()
        if self._client is None:
            self._client = LogsQueryClient(self._credential)

    def collect(self, request: CollectionRequest) -> CollectionResult:
        self._ensure_client()
        events: list[TimelineEvent] = []
        error = None
        computer = request.machine.vm_name

        heartbeat_started = time.monotonic()
        try:
            heartbeat_events = self._heartbeat_events(request, computer)
            log.info(
                "azure_monitor: heartbeat query for %s returned %d event(s) after %.1fs",
                computer, len(heartbeat_events), time.monotonic() - heartbeat_started,
            )
            events.extend(heartbeat_events)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "azure_monitor: heartbeat query for %s failed after %.1fs (%s)",
                computer, time.monotonic() - heartbeat_started, safe_exc_summary(exc),
            )
            error = f"Heartbeat query failed: {exc}"

        event_started = time.monotonic()
        try:
            # No `else` branch - an OSFamily.UNKNOWN machine gets no
            # event/syslog query attempted at all (unchanged from before),
            # so nothing is logged for it either; logging "0 events" here
            # would misleadingly imply a query ran when none did.
            if request.machine.os_family == OSFamily.WINDOWS:
                event_results = self._run_event_query(_WINDOWS_EVENT_QUERY, request, computer, Source.AZURE_MONITOR)
            elif request.machine.os_family == OSFamily.LINUX:
                event_results = self._run_event_query(_LINUX_SYSLOG_QUERY, request, computer, Source.AZURE_MONITOR)
            else:
                event_results = None
            if event_results is not None:
                log.info(
                    "azure_monitor: event/syslog query for %s returned %d event(s) after %.1fs",
                    computer, len(event_results), time.monotonic() - event_started,
                )
                events.extend(event_results)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "azure_monitor: event/syslog query for %s failed after %.1fs (%s)",
                computer, time.monotonic() - event_started, safe_exc_summary(exc),
            )
            error = (error + "; " if error else "") + f"Event/Syslog query failed: {exc}"

        return CollectionResult(events=events, error=error, checks_finding_counts=non_guest_finding_counts(Source.AZURE_MONITOR, events))

    def _heartbeat_events(self, request: CollectionRequest, computer: str) -> list[TimelineEvent]:
        from culprit.security.kql import escape_kql_string

        gap_check_start = request.window_start - timedelta(hours=6)
        query = _HEARTBEAT_QUERY.format(
            computer=escape_kql_string(computer),
            vm_id=escape_kql_string(request.machine.vm_id),
            gap_check_start=gap_check_start.isoformat(),
            window_end=request.window_end.isoformat(),
        )
        response = self._client.query_workspace(self.workspace_id, query, timespan=None)
        if response.status != LogsQueryStatus.SUCCESS:
            # Found 2026-10-15: this used to be folded into the same
            # branch as "query succeeded, genuinely zero rows" below -
            # a failed/partial KQL call (auth hiccup, throttling) was
            # reported to the RCA agent as *positive evidence* of an
            # unresponsive guest agent, a false signal, not just a
            # missing one. Raising here routes it through collect()'s own
            # try/except into a normal collection_gaps entry instead.
            raise RuntimeError(f"Heartbeat query did not succeed (status={response.status})")
        if not response.tables or not response.tables[0].rows:
            # No heartbeat row at all in the lookback window is itself the signal.
            return [
                TimelineEvent(
                    ts=request.window_end,
                    source=Source.AZURE_MONITOR,
                    kind="heartbeat_gap",
                    summary="No Heartbeat rows found spanning the maintenance window",
                    detail={"agent_unresponsive": True},
                    raw_ref=f"loganalytics:heartbeat:{request.machine.vm_id}:{request.window_start.isoformat()}",
                )
            ]

        last_beat = response.tables[0].rows[0][0]
        if last_beat is None or last_beat < request.window_start:
            return [
                TimelineEvent(
                    ts=last_beat or request.window_start,
                    source=Source.AZURE_MONITOR,
                    kind="heartbeat_gap",
                    summary=f"Last heartbeat at {last_beat} predates the window start {request.window_start}",
                    detail={"agent_unresponsive": True},
                    raw_ref=f"loganalytics:heartbeat:{request.machine.vm_id}:{request.window_start.isoformat()}",
                )
            ]
        return []

    def _run_event_query(self, template: str, request: CollectionRequest, computer: str, source: Source) -> list[TimelineEvent]:
        from culprit.security.kql import escape_kql_string

        query = template.format(
            computer=escape_kql_string(computer),
            window_start=request.window_start.isoformat(),
            window_end=request.window_end.isoformat(),
        )
        response = self._client.query_workspace(self.workspace_id, query, timespan=None)
        if response.status != LogsQueryStatus.SUCCESS:
            # Same fix as _heartbeat_events above - this used to silently
            # return [] with no trace at all, indistinguishable from "ran
            # fine, found nothing to report."
            raise RuntimeError(f"{source.value} query did not succeed (status={response.status})")
        out: list[TimelineEvent] = []
        for table in response.tables:
            for row in table.rows:
                ts, *rest = row
                message = " ".join(str(r) for r in rest if r)
                out.append(
                    TimelineEvent(
                        ts=ts,
                        source=source,
                        kind="guest_log_via_monitor",
                        summary=message[:240],
                        detail={
                            "lock_held": "lock" in message.lower() and "held" in message.lower(),
                            "write_failure": "no space left on device" in message.lower(),
                            "disk_low": "no space left on device" in message.lower(),
                        },
                        raw_ref=f"loganalytics:{source.value}:{request.machine.vm_id}:{ts}",
                    )
                )
        return out
