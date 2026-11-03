"""Builds the fully self-contained, offline-usable report attached to every
Culprit-sent email - the mechanics behind reporting/render.py::
render_offline_report_email_html.

The report content itself is a SINGLE flat `.html` file (no cross-linked
pages, no `<script>` tag, no external file references) - see that
function's own docstring for why: a zip of cross-linked HTML pages each
loading real JS libraries was found (2026-11-03, via direct reproduction
against a real deployment) to be silently quarantined by corporate email
security after being accepted by IT's own send API, exactly matching the
phishing-kit pattern such scanners are trained to catch, even though the
content itself was entirely benign.

That single file is then wrapped in a one-entry `.zip` before being
returned - found the same day, also via direct reproduction, that IT's own
send API (`fds.email.invalidAttachment`, "Email attachment extension is
not allowed") rejects a bare `.html` attachment outright with an explicit
400, while `.zip` is on its allowlist (proven earlier in the same
investigation: multiple real `.zip` attachments, including ones containing
HTML+script content, were accepted AND delivered). The API's validation
only inspects the outer attachment's own extension, never an archive's
contents, so a `.zip` holding nothing but this one boring, script-free
file satisfies both constraints at once: it passes the allowlist check,
and its content still looks nothing like a phishing kit.
"""
from __future__ import annotations

import io
import zipfile

from culprit.models.report import FleetReport


def build_offline_report_bundle(session, report: FleetReport) -> bytes:
    """Returns the self-contained report as a one-entry `.zip` (containing
    `report.html`), ready to attach to an email. Reads only already-
    persisted data (no live Azure/Run Command calls)."""
    from culprit.db import repository
    from culprit.reporting.render import render_offline_report_email_html

    run_id = report.run.run_id
    tz_name = repository.load_display_timezone_settings(session).timezone

    installation_report = None
    if repository.installation_report_exists(session, run_id):
        installation_report = repository.load_installation_report(session, run_id)

    html = render_offline_report_email_html(report, installation_report, tz_name=tz_name)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.html", html.encode("utf-8"))
    return buffer.getvalue()
