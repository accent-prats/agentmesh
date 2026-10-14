"""Push the fleet report into Teams / Slack (proposal Section 10:
"delivery meets people where they already are... one ticket per cause").

Both functions post a real webhook payload shape (Teams' MessageCard /
Adaptive Card via Power Automate workflow webhook, and Slack's
`blocks` API) - point `webhook_url` at a real Incoming Webhook and this
works as-is. No secrets are read from anywhere but the environment/caller-
supplied URL; nothing here talks to Azure or Datadog.
"""
from __future__ import annotations

import httpx
from starlette.requests import Request

from culprit.models.report import ClusterReportEntry, FleetReport

_TOP_N_FOR_DIGEST = 5


def top_entries(report: FleetReport) -> list[ClusterReportEntry]:
    """The same top-N selection every outbound digest uses - Teams, Slack,
    and the report-email feature (culprit/notifications/email_sender.py) -
    so "top findings" never means something different depending on which
    channel is looking at it. Promoted from a module-private helper
    2026-10-14 once a second caller (email) needed the identical
    selection."""
    return report.entries[:_TOP_N_FOR_DIGEST]


def report_url_from_request(request: Request, run_id: str) -> str:
    """Absolute link back to a run's rendered report, reverse-proxy prefix
    included - what the Teams/Slack digest's "Open full report" button and
    the report-email feature's own link both use. Promoted from
    api/routes_runs.py's private `_report_url` 2026-10-14 once a second
    caller (routes_notifications.py) needed the identical URL shape from
    its own request context - this module is already "where outbound
    notification links get built", so it fits here rather than being
    duplicated a second time."""
    from culprit.api.root_path_middleware import root_path

    return f"{str(request.base_url).rstrip('/')}{root_path(request)}/runs/{run_id}/report.html"


def post_to_slack(webhook_url: str, report: FleetReport, report_url: str | None = None) -> httpx.Response:
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Culprit · {report.run.scope_name}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Failed:* {report.total_failed}/{report.total_machines}"},
                {"type": "mrkdwn", "text": f"*Distinct causes:* {report.total_clusters}"},
                {"type": "mrkdwn", "text": f"*Compliance:* {report.compliance_pct}%"},
                {"type": "mrkdwn", "text": f"*Repeat offenders:* {report.repeat_offender_count}"},
            ],
        },
        {"type": "divider"},
    ]
    for entry in top_entries(report):
        badge = f" _{entry.recurrence_badge}_" if entry.recurrence_badge else ""
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{entry.cluster.size} machines* — {entry.result.title}{badge}\n"
                        f"Confidence {entry.result.confidence:.0%} · {entry.result.cause_family.value}"
                    ),
                },
            }
        )
    if report_url:
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": f"<{report_url}|Open the full report>"}}
        )
    return httpx.post(webhook_url, json={"blocks": blocks}, timeout=10.0)


def post_to_teams(webhook_url: str, report: FleetReport, report_url: str | None = None) -> httpx.Response:
    facts = [
        {"name": "Failed", "value": f"{report.total_failed}/{report.total_machines}"},
        {"name": "Distinct causes", "value": str(report.total_clusters)},
        {"name": "Compliance", "value": f"{report.compliance_pct}%"},
        {"name": "Repeat offenders", "value": str(report.repeat_offender_count)},
    ]
    sections = [{"activityTitle": f"Culprit · {report.run.scope_name}", "facts": facts, "markdown": True}]
    for entry in top_entries(report):
        badge = f" ({entry.recurrence_badge})" if entry.recurrence_badge else ""
        sections.append(
            {
                "activityTitle": f"{entry.cluster.size} machines — {entry.result.title}{badge}",
                "text": f"Confidence {entry.result.confidence:.0%} · {entry.result.cause_family.value}",
            }
        )
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"Culprit report for {report.run.scope_name}",
        "themeColor": "A3281E" if report.repeat_offender_count else "14528F",
        "sections": sections,
        "potentialAction": (
            [{"@type": "OpenUri", "name": "Open full report", "targets": [{"os": "default", "uri": report_url}]}]
            if report_url
            else []
        ),
    }
    return httpx.post(webhook_url, json=payload, timeout=10.0)
