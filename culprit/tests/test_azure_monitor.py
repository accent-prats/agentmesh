"""collectors/azure_monitor.py - had zero test coverage before this, same
gap test_azure_control_plane.py closed earlier this session for its own
collector. Covers the exact bug found 2026-10-15: a non-SUCCESS Log
Analytics query status used to be treated identically to "query succeeded,
genuinely zero rows" in _heartbeat_events - a failed/partial KQL call (auth
hiccup, throttling) was reported to the RCA agent as *positive evidence* of
an unresponsive guest agent, a false signal, not just a missing one.
_run_event_query had the milder version: a non-SUCCESS status silently
returned [] with no trace at all."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("azure.monitor.query")  # optional `culprit[azure]` extra - see pyproject.toml

from azure.monitor.query import LogsQueryStatus

from culprit.collectors.azure_monitor import AzureMonitorCollector
from culprit.collectors.base import CollectionRequest
from culprit.models.evidence import MachineIdentity, OSFamily, Source


class _FakeTable:
    def __init__(self, rows):
        self.rows = rows


class _FakeResponse:
    def __init__(self, status, tables=None):
        self.status = status
        self.tables = tables or []


class _FakeLogsQueryClient:
    """Routes by query text (Heartbeat vs Event/Syslog templates each
    start with their own table name - azure_monitor.py's own
    _HEARTBEAT_QUERY/_WINDOWS_EVENT_QUERY/_LINUX_SYSLOG_QUERY), so each
    test can isolate one query's response without the other interfering -
    collect() always runs both."""

    def __init__(self, heartbeat_response, event_response):
        self._heartbeat_response = heartbeat_response
        self._event_response = event_response

    def query_workspace(self, workspace_id, query, timespan=None):
        return self._heartbeat_response if query.strip().startswith("Heartbeat") else self._event_response


def _machine(os_family=OSFamily.LINUX):
    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=os_family,
    )


def _request():
    now = datetime.now(timezone.utc)
    return CollectionRequest(machine=_machine(), window_start=now - timedelta(hours=3), window_end=now, run_id="run-1")


_OK_HEARTBEAT = _FakeResponse(status=LogsQueryStatus.SUCCESS, tables=[_FakeTable(rows=[[datetime.now(timezone.utc)]])])
_OK_EVENTS = _FakeResponse(status=LogsQueryStatus.SUCCESS, tables=[])


def _collector(heartbeat_response=_OK_HEARTBEAT, event_response=_OK_EVENTS):
    collector = AzureMonitorCollector(workspace_id="workspace-1", credential=object())
    collector._client = _FakeLogsQueryClient(heartbeat_response, event_response)
    return collector


def test_a_failed_heartbeat_query_becomes_a_collection_gap_not_a_false_positive():
    """The core regression: a non-SUCCESS status must not be reported as
    'agent unresponsive' - that's fabricating evidence from a broken
    query, not a real signal."""
    collector = _collector(heartbeat_response=_FakeResponse(status=LogsQueryStatus.PARTIAL))
    result = collector.collect(_request())

    assert result.error is not None
    assert "Heartbeat query" in result.error
    assert not any(e.kind == "heartbeat_gap" for e in result.events)


def test_a_genuinely_empty_heartbeat_result_still_produces_the_real_gap_event():
    """Don't regress the legitimate case this was built for - a query that
    actually succeeded with zero rows is real evidence of an unresponsive
    agent."""
    collector = _collector(heartbeat_response=_FakeResponse(status=LogsQueryStatus.SUCCESS, tables=[_FakeTable(rows=[])]))
    result = collector.collect(_request())

    assert result.error is None
    assert any(e.kind == "heartbeat_gap" and e.detail.get("agent_unresponsive") for e in result.events)


def test_a_failed_event_query_becomes_a_collection_gap_not_silence():
    """_run_event_query's own version of the same bug - used to just
    return [] with zero trace on a non-SUCCESS status."""
    collector = _collector(event_response=_FakeResponse(status=LogsQueryStatus.FAILURE))
    result = collector.collect(_request())

    assert result.error is not None
    assert "query did not succeed" in result.error
