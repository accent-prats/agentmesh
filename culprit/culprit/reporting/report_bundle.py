"""Builds a fully self-contained, offline-usable copy of a run's report -
the attachment behind the auto-send-on-completion feature
(notifications/auto_report_email.py).

Every existing report page (Fleet Report, Installation Report, each
machine's own detail page) already links to its siblings with literal
RELATIVE paths that assume the live app's own route structure:
`/runs/{run_id}/report.html`, `/runs/{run_id}/installation-report.html`,
`/runs/{run_id}/machines/{vm_name}.html`. Rather than rewriting any
template to carry an absolute base URL, this module reproduces that EXACT
nested folder structure inside a zip - every one of those existing relative
hrefs then resolves correctly once the zip is extracted and `report.html`
is opened via `file://`, with zero template changes. The one external asset
every page's styling depends on (`static/tailwind.js`, served live by
api/main.py's own static route) is copied in alongside it for the same
reason - without it, the pages would render completely unstyled offline.
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

from culprit.models.report import FleetReport

_STATIC_DIR = Path(__file__).parent / "static"


def build_offline_report_bundle(session, report: FleetReport) -> bytes:
    """Returns the bundle as zip bytes, ready to attach to an email or save
    to disk. Reads only already-persisted data (no live Azure/Run Command
    calls) - fast even for a large fleet."""
    from culprit.db import repository
    from culprit.reporting.render import (
        render_fleet_report_html_for_run,
        render_installation_report_html,
        render_machine_html,
    )

    run_id = report.run.run_id
    tz_name = repository.load_display_timezone_settings(session).timezone

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"runs/{run_id}/report.html", render_fleet_report_html_for_run(session, run_id, report))

        if repository.installation_report_exists(session, run_id):
            installation_report = repository.load_installation_report(session, run_id)
            zf.writestr(
                f"runs/{run_id}/installation-report.html",
                render_installation_report_html(installation_report, tz_name=tz_name),
            )

        # Every vm_name the Fleet Report's own machines/{vm}.html links
        # point at - report.machine_rows is already the flat, one-row-per-
        # machine view the report's own table is built from (models/
        # report.py::FleetReport.machine_rows), so this is exactly the set
        # of pages those links need to resolve.
        for vm_name in {row.vm_name for row in report.machine_rows}:
            detail = repository.get_machine_detail(session, run_id, vm_name)
            if detail is None:
                continue
            machine_html = render_machine_html(
                detail.cluster, detail.member, detail.result, detail.outcome, detail.collection_gaps,
                detail.patch_extension_status, detail.timeline, detail.checks_performed,
                detail.checks_unavailable, detail.sources_attempted, detail.checks_finding_counts, tz_name=tz_name,
            )
            zf.writestr(f"runs/{run_id}/machines/{vm_name}.html", machine_html)

        tailwind_js = _STATIC_DIR / "tailwind.js"
        if tailwind_js.exists():
            zf.writestr("static/tailwind.js", tailwind_js.read_bytes())

    return buffer.getvalue()
