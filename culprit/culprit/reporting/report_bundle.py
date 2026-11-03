"""Builds the fully self-contained, offline-usable report attached to every
Culprit-sent email - the mechanics behind reporting/render.py::
render_offline_report_email_html.

A SINGLE flat `.html` file, not a zip of linked pages - see that function's
own docstring for why: a zip of cross-linked HTML pages each loading real
JS libraries was found (2026-11-03, via direct reproduction against a real
deployment) to be silently quarantined by corporate email security after
being accepted by IT's own send API, exactly matching the phishing-kit
pattern such scanners are trained to catch, even though the content itself
was entirely benign. One flat file with no `<script>` tag and no external
file references is deliberately "boring" to avoid that classification.
"""
from __future__ import annotations

from culprit.models.report import FleetReport


def build_offline_report_bundle(session, report: FleetReport) -> bytes:
    """Returns the self-contained report as UTF-8 HTML bytes, ready to
    attach to an email. Reads only already-persisted data (no live Azure/
    Run Command calls)."""
    from culprit.db import repository
    from culprit.reporting.render import render_offline_report_email_html

    run_id = report.run.run_id
    tz_name = repository.load_display_timezone_settings(session).timezone

    installation_report = None
    if repository.installation_report_exists(session, run_id):
        installation_report = repository.load_installation_report(session, run_id)

    html = render_offline_report_email_html(report, installation_report, tz_name=tz_name)
    return html.encode("utf-8")
