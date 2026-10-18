"""collectors/datadog_collector.py - had no dedicated test file before
this. Focused on checks_finding_counts (added by review 2026-10-19): this
collector's logs query has no cap at all, and the metrics/monitors
branches aren't capped either - exposing it to the same persisted-
timeline eviction risk already fixed for the guest collectors (a genuine
finding silently dropped from the capped, persisted timeline would make
the "logs used/not used" reconciliation wrongly report "no issues
found"). checks_finding_counts records the TRUE, uncapped total at
collection time instead."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("datadog_api_client")  # optional `culprit[datadog]` extra - see pyproject.toml

import culprit.collectors.datadog_collector as datadog_collector
from culprit.collectors.base import CollectionRequest
from culprit.collectors.datadog_collector import DatadogCollector
from culprit.models.evidence import MachineIdentity, OSFamily


class _EmptyMetricsApi:
    def __init__(self, client):
        pass

    def query_metrics(self, _from, to, query):
        class _Response:
            series = []
        return _Response()


class _QuietMonitorsApi:
    def __init__(self, client):
        pass

    def list_monitors(self, monitor_tags):
        return []


class _AlertingMonitorsApi:
    def __init__(self, client):
        pass

    def list_monitors(self, monitor_tags):
        class _Monitor:
            id = 1
            name = "boot partition full"
            overall_state = "Alert"
        return [_Monitor()]


class _EmptyLogsApi:
    def __init__(self, client):
        pass

    def list_logs(self, body):
        class _Response:
            data = []
        return _Response()


def _request():
    now = datetime.now(timezone.utc)
    machine = MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )
    return CollectionRequest(machine=machine, window_start=now - timedelta(hours=3), window_end=now, run_id="run-1")


def _collector(monkeypatch, metrics_api=_EmptyMetricsApi, monitors_api=_QuietMonitorsApi, logs_api=_EmptyLogsApi):
    monkeypatch.setattr(datadog_collector, "MetricsApi", metrics_api)
    monkeypatch.setattr(datadog_collector, "MonitorsApi", monitors_api)
    monkeypatch.setattr(datadog_collector, "LogsApi", logs_api)
    collector = DatadogCollector()
    collector._api_client = object()  # bypass _ensure_client's real auth/config resolution
    return collector


def test_checks_finding_counts_is_empty_when_nothing_was_found(monkeypatch):
    collector = _collector(monkeypatch)
    result = collector.collect(_request())
    assert result.events == []
    assert result.checks_finding_counts == {}


def test_checks_finding_counts_reflects_the_true_event_count(monkeypatch):
    collector = _collector(monkeypatch, monitors_api=_AlertingMonitorsApi)
    result = collector.collect(_request())

    assert len(result.events) == 1
    assert result.checks_finding_counts == {"Datadog (metrics, monitors, logs)": 1}
