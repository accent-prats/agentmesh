"""Datadog collector: metrics (preconditions leading into the window),
monitor state, and logs/events (post-reboot regression detection).

Requires `datadog-api-client`, and `DD_API_KEY` / `DD_APP_KEY` /
`DD_SITE` in the environment (standard Datadog client env vars - this
module never reads a raw HTTP endpoint directly). Read-only: every call
below is `query_metrics` / `list_monitors` / `list_logs_get`, never a
mutating Datadog API.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from culprit.collectors.base import CollectionRequest, CollectionResult, Collector
from culprit.models.evidence import Source, TimelineEvent

try:  # pragma: no cover
    from datadog_api_client import ApiClient, Configuration
    from datadog_api_client.v1.api.metrics_api import MetricsApi
    from datadog_api_client.v1.api.monitors_api import MonitorsApi
    from datadog_api_client.v2.api.logs_api import LogsApi
    from datadog_api_client.v2.model.logs_list_request import LogsListRequest
    from datadog_api_client.v2.model.logs_query_filter import LogsQueryFilter

    _DATADOG_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _DATADOG_SDK_AVAILABLE = False


# Metric queries evaluated over the lead-up window (T-7d -> T+1d per the
# proposal's evidence table). Extend this list as Phase 0 identifies which
# metrics actually correlate with failures on this estate's images.
_PRECONDITION_METRIC_QUERIES: dict[str, str] = {
    "disk_root": "avg:system.disk.in_use{{mount:/}} by {{host}}",
    "disk_boot": "avg:system.disk.in_use{{mount:/boot}} by {{host}}",
    "disk_var": "avg:system.disk.in_use{{mount:/var}} by {{host}}",
    "mem_pressure": "avg:system.mem.pct_usable{{host:{host}}}",
}

_DISK_ALERT_RATIO = 0.85


class DatadogCollector(Collector):
    source_name = "datadog"

    def __init__(self, settings=None):
        # `settings` is a culprit.models.settings.DatadogSettingsInput -
        # typically loaded from the /culprit/settings screen via
        # culprit.db.repository.load_datadog_settings. None falls back to
        # the datadog-api-client's own env-var resolution
        # (DD_API_KEY/DD_APP_KEY/DD_SITE), unchanged from before.
        self._settings = settings
        self._api_client = None

    def _ensure_client(self):
        if not _DATADOG_SDK_AVAILABLE:
            raise RuntimeError(
                "datadog-api-client is not installed. pip install it, "
                "or use the demo collector for offline runs."
            )
        if self._api_client is None:
            configuration = Configuration()
            if self._settings and self._settings.api_key:
                configuration.api_key["apiKeyAuth"] = self._settings.api_key
                if self._settings.app_key:
                    configuration.api_key["appKeyAuth"] = self._settings.app_key
                configuration.server_variables["site"] = self._settings.site or "datadoghq.com"
            self._api_client = ApiClient(configuration)
        return self._api_client

    def collect(self, request: CollectionRequest) -> CollectionResult:
        client = self._ensure_client()
        events: list[TimelineEvent] = []
        error = None
        host = request.machine.vm_name

        lookback_start = int((request.window_start - timedelta(days=7)).timestamp())
        lookahead_end = int((request.window_end + timedelta(days=1)).timestamp())

        try:
            metrics_api = MetricsApi(client)
            for label, query_tmpl in _PRECONDITION_METRIC_QUERIES.items():
                query = query_tmpl.format(host=host)
                response = metrics_api.query_metrics(_from=lookback_start, to=lookahead_end, query=query)
                events.extend(_events_from_metric_series(response, label, request))
        except Exception as exc:  # noqa: BLE001
            error = f"Datadog metrics query failed: {exc}"

        try:
            monitors_api = MonitorsApi(client)
            monitors = monitors_api.list_monitors(monitor_tags=f"host:{host}")
            for monitor in monitors:
                if monitor.overall_state and str(monitor.overall_state) in ("Alert", "Warn"):
                    events.append(
                        TimelineEvent(
                            ts=datetime.now(timezone.utc),
                            source=Source.DATADOG_MONITOR,
                            kind="monitor_state",
                            summary=f"Monitor '{monitor.name}' state={monitor.overall_state}",
                            detail={"monitor_id": monitor.id},
                            raw_ref=f"datadog:monitor:{monitor.id}",
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            error = (error + "; " if error else "") + f"Datadog monitors query failed: {exc}"

        try:
            logs_api = LogsApi(client)
            body = LogsListRequest(
                filter=LogsQueryFilter(
                    query=f"host:{host}",
                    _from=request.window_start.isoformat(),
                    to=(request.window_end + timedelta(hours=1)).isoformat(),
                )
            )
            response = logs_api.list_logs(body=body)
            for log in getattr(response, "data", []) or []:
                attrs = log.attributes
                message = getattr(attrs, "message", "") or ""
                if getattr(attrs, "status", "") in ("error", "critical") or "failed to start" in message.lower():
                    events.append(
                        TimelineEvent(
                            ts=getattr(attrs, "timestamp", None) or datetime.now(timezone.utc),
                            source=Source.DATADOG_LOG,
                            kind="post_reboot_log",
                            summary=message[:240],
                            detail={"post_patch_regression_signal": True},
                            raw_ref=f"datadog:log:{log.id}",
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            error = (error + "; " if error else "") + f"Datadog logs query failed: {exc}"

        return CollectionResult(events=events, error=error)


def _events_from_metric_series(response, label: str, request: CollectionRequest) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    series = getattr(response, "series", None) or []
    for s in series:
        points = getattr(s, "pointlist", None) or []
        if not points:
            continue
        first_val = points[0][1]
        last_val = points[-1][1]
        if last_val is None:
            continue
        trend = "rising" if first_val is not None and last_val > first_val else "flat/falling"
        events.append(
            TimelineEvent(
                ts=request.window_start,
                source=Source.DATADOG_METRIC,
                kind="metric_trend",
                summary=f"{label} = {last_val:.2f} at window start ({trend} over lookback)",
                detail={
                    "disk_low": "disk" in label and last_val is not None and last_val >= _DISK_ALERT_RATIO,
                    "mount": {"disk_root": "/", "disk_boot": "/boot", "disk_var": "/var"}.get(label, ""),
                    "metric": label,
                    "value": last_val,
                },
                raw_ref=f"datadog:metric:{label}:{request.machine.vm_id}",
            )
        )
    return events
