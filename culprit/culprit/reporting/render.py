"""Render a FleetReport to HTML."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from culprit.models.installation_report import InstallationReport
from culprit.models.report import FleetReport

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env() -> Environment:
    # remediation_enabled is a Jinja *global*, not a per-call render
    # kwarg, specifically so base.html.j2's shared nav (extended by every
    # page) can gate the "Remediation log" link on it without threading
    # a new parameter through every single render_*_html function and
    # call site - every template already goes through this one function,
    # so this is the one place that needs to know about the flag at all.
    # supported_action_families is static, process-wide config too (not
    # per-request data like family_precision, which stays an explicit
    # render parameter) - same reasoning, same treatment.
    #
    # promotion_threshold/promotion_min_sample are deliberately NOT here
    # any more (moved 2026-10-14, "make the gate editable" feature) - they
    # used to be read straight from config.settings, but they're now a
    # DB-backed value the Settings screen can override at runtime
    # (repository.py::get_current_promotion_gate), so each render call
    # that needs them takes them as an explicit parameter instead, same
    # as family_precision - a Jinja global set once per Environment
    # construction would go stale the moment someone saved a new gate
    # value without a process restart.
    from culprit.config import settings
    from culprit.models.remediation import SUPPORTED_ACTIONS
    from culprit.models.settings import GATE_MIN_SAMPLE_FLOOR, GATE_THRESHOLD_FLOOR

    # Found in review 2026-10-14 (the "email a report" feature): every
    # template this app has is named "*.html.j2", but select_autoescape
    # matches on a template name's actual final suffix - ".j2", not
    # ".html" - so select_autoescape(["html"]) silently returned False
    # for every single page this app has ever rendered, and autoescaping
    # has been off app-wide since this file was first written. Every
    # template here genuinely is HTML and always has been, so there is no
    # case where escaping should be skipped - autoescape=True
    # unconditionally, not another attempt at extension-matching.
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    env.globals["remediation_enabled"] = settings.remediation_enabled
    # "/" (site root) unless this deployment set CULPRIT_PORTAL_PUBLIC_URL
    # because Culprit's own origin isn't also Portal's - see
    # config.py::portal_public_url's own comment.
    env.globals["portal_url"] = settings.portal_public_url or "/"
    env.globals["supported_action_families"] = SUPPORTED_ACTIONS
    # The gate's editable floor (see models/settings.py) - genuinely
    # static, unlike promotion_threshold/promotion_min_sample above, so
    # this gets the same global treatment supported_action_families does.
    env.globals["gate_threshold_floor"] = GATE_THRESHOLD_FLOOR
    env.globals["gate_min_sample_floor"] = GATE_MIN_SAMPLE_FLOOR
    return env


def render_fleet_report_html(
    report: FleetReport, family_precision=None, promotion_threshold: float = 0.95, promotion_min_sample: int = 50,
    smtp_configured: bool = False, default_recipients: list | None = None,
) -> str:
    """`family_precision` (dict[CauseFamily, FamilyPrecision]) is a
    render-only input, deliberately kept off `FleetReport` itself (that
    model is also returned as plain JSON from GET /runs/{run_id}/report) -
    same "UI-only data stays a render parameter, not a model field"
    convention render_console_html already uses for `demo_enabled`. Used
    to decide what the "Run remediation" control under each cluster's
    Automation candidate badge shows once a family clears the gate - see
    routes_runs.py::get_report_html for where it (and promotion_threshold/
    promotion_min_sample, via repository.py::get_current_promotion_gate)
    are computed.
    `remediation_enabled` itself is a Jinja global (see _env()), not
    passed here - whether the button exists at all vs. not rendering is
    gated in the template directly."""
    template = _env().get_template("fleet_report.html.j2")
    # This page lives two levels below the app root (runs/{id}/report.html),
    # unlike every other page here - nav_prefix corrects the shared sidebar's
    # otherwise-root-relative links (base.html.j2) so they still resolve
    # correctly from this depth.
    return template.render(
        report=report, active="console", nav_prefix="../../", family_precision=family_precision or {},
        promotion_threshold=promotion_threshold, promotion_min_sample=promotion_min_sample,
        smtp_configured=smtp_configured, default_recipients=default_recipients or [],
    )


def render_installation_report_html(report: InstallationReport) -> str:
    """The Azure Update Manager-style full-fleet view
    (models/installation_report.py) - lives at the same depth as
    report.html (runs/{id}/installation-report.html), same nav_prefix."""
    template = _env().get_template("installation_report.html.j2")
    return template.render(report=report, active="console", nav_prefix="../../")


def render_runs_html(runs, demo_enabled: bool = True) -> str:
    """The Runs list page - "which update jobs is Culprit monitoring",
    most recent first (culprit/db/repository.py::list_runs). Root-level,
    same depth as console/settings/precision.html. `demo_enabled` only
    affects the empty-state copy (it points at the Console's demo
    button, which shouldn't be mentioned when that button doesn't
    exist) - see render_console_html.

    `distinct_triggers`/`distinct_stages` populate the toolbar's filter
    dropdowns - derived from whatever's actually present in `runs` (not
    the full TriggerMode/RunStage enums) so a value nothing has ever used
    yet doesn't show up as a dead filter option, and a new trigger/stage
    value needs no template change to filter on once something actually
    uses it. Sorted for a stable render (set iteration order isn't)."""
    template = _env().get_template("runs.html.j2")
    distinct_triggers = sorted({r.trigger_mode for r in runs})
    distinct_stages = sorted({r.stage for r in runs})
    return template.render(
        runs=runs, active="runs", demo_enabled=demo_enabled,
        distinct_triggers=distinct_triggers, distinct_stages=distinct_stages,
    )


def _trend_chart_geometry(trend, width: int = 300, height: int = 72, pad_x: float = 4, pad_y: float = 8):
    """SVG coordinates for the Console dashboard's compliance trend line.
    Computed here, not in the template - scaling the line to its own
    data's min/max (not a fixed 0-100 axis, which would flatten real-world
    compliance% variation most runs never leave the 80-100 band in to a
    near-flat line) is a float computation across every point, not a
    single Jinja filter expression."""
    values = [p.compliance_pct for p in trend]
    lo, hi = min(values), max(values)
    if hi == lo:  # every point identical - avoid a divide by zero, draw a flat middle line instead
        lo, hi = lo - 1, hi + 1

    n = len(trend)
    points = []
    for i, p in enumerate(trend):
        x = width / 2 if n == 1 else pad_x + (i / (n - 1)) * (width - 2 * pad_x)
        y = pad_y + (1 - (p.compliance_pct - lo) / (hi - lo)) * (height - 2 * pad_y)
        points.append({"x": round(x, 1), "y": round(y, 1), "pct": p.compliance_pct, "date": p.started_at.strftime("%Y-%m-%d")})

    return {
        "width": width,
        "height": height,
        "points": points,
        "polyline": " ".join(f"{pt['x']},{pt['y']}" for pt in points),
    }


def render_console_html(demo_enabled: bool = True, dashboard=None) -> str:
    """The app's landing page - what the AgentMesh launcher's 'Launch'
    button sends people to, and now a real dashboard (see
    db/repository.py::build_dashboard_summary /
    models/dashboard.py::DashboardSummary), not just a launcher.
    `active` just drives which sidebar nav item (in base.html.j2, shared
    with every Culprit page) is highlighted. `demo_enabled` hides the
    "Demo scenario" card to match api/routes_runs.py's own
    config.settings.demo_enabled-gated route - see config.py.
    `dashboard` defaults to an empty DashboardSummary (not None passed
    through) so the template never has to guard against a missing
    object, only against its fields being empty - the same "absence
    isn't an error" shape as FleetTrend/DashboardSummary.latest_run."""
    from culprit.models.dashboard import DashboardSummary

    dashboard = dashboard or DashboardSummary()
    # Fewer than 2 points isn't a trend, it's a dot - same "nothing to
    # compare against yet" shape as FleetTrend being None for a first cycle.
    trend_chart = _trend_chart_geometry(dashboard.compliance_trend) if len(dashboard.compliance_trend) >= 2 else None

    template = _env().get_template("console.html.j2")
    return template.render(active="console", demo_enabled=demo_enabled, dashboard=dashboard, trend_chart=trend_chart)


def render_settings_html() -> str:
    """The Azure/Datadog connection settings screen - reads and writes
    culprit/api/routes_settings.py entirely client-side via fetch()."""
    template = _env().get_template("settings.html.j2")
    return template.render(active="settings")


def render_machine_html(cluster, member, result, outcome=None, collection_gaps=None) -> str:
    """The third report altitude (proposal Section 8): one machine's own
    timeline deviation from its cluster's representative, plus its own
    `PatchOutcome` (status, error, failed KB/package) when this run saved
    one - see MachineOutcomeRecord; `outcome` is None for runs diagnosed
    before that existed, not an error. Lives three levels below the app
    root (runs/{id}/machines/{vm_id}.html), hence the deeper nav_prefix -
    see render_fleet_report_html's comment."""
    template = _env().get_template("machine.html.j2")
    return template.render(
        cluster=cluster, member=member, result=result, outcome=outcome, collection_gaps=collection_gaps or [],
        active="console", nav_prefix="../../../",
    )


def render_precision_html(precision: dict) -> str:
    """The Phase 2 promotion gate (proposal Section 11), rendered - per-
    family precision, sample size, and whether each family currently
    clears the promotion bar."""
    template = _env().get_template("precision.html.j2")
    return template.render(active="precision", precision=precision)


def render_remediation_log_html(records) -> str:
    """The Phase 2 remediation audit log - every automated action ever
    taken, most recent first (culprit/db/repository.py::
    list_remediation_actions). Served at /remediation/log.html - one level
    below the app root (routes_remediation.py's router has
    prefix="/remediation") - nav_prefix corrects the shared sidebar's
    otherwise-root-relative links/static assets so they still resolve
    correctly from this depth, same reasoning as render_fleet_report_html's
    own nav_prefix. Found live via Playwright: without this, the page
    requested static/tailwind.js as /remediation/static/tailwind.js and
    rendered completely unstyled."""
    template = _env().get_template("remediation_log.html.j2")
    return template.render(active="remediation", records=records, nav_prefix="../")


def render_email_report_html(report: FleetReport, top_entries: list, report_url: str | None, note: str, requested_by: str) -> str:
    """The HTML body of a "Email report" send (api/routes_notifications.py,
    culprit/notifications/email_sender.py) - standalone (no `extends
    base.html.j2`, same reasoning as render_login_html: nothing to put in
    a sidebar for an email client to render, and no Tailwind CDN script
    either, since email clients strip <script>/external <link> tags - this
    template is plain inline-styled HTML, a different rendering contract
    from every other page `_env()` serves. `top_entries` is
    notify.py::top_entries(report)'s own selection, reused rather than
    duplicated so the email's "top findings" list always matches the
    Teams/Slack digest's."""
    template = _env().get_template("email_report.html.j2")
    return template.render(report=report, top_entries=top_entries, report_url=report_url, note=note, requested_by=requested_by)


def render_login_html(next_path: str = "/", error: str = "", show_token_login: bool = True) -> str:
    """The shared-token sign-in page (culprit/api/auth_middleware.py) -
    doesn't extend base.html.j2, since there's nothing to put in the
    sidebar for someone who isn't authenticated yet. `next_path` and
    `error` are plain Jinja variables, autoescaped like every other
    template here - the XSS finding from review was in settings.html.j2's
    client-side JS, not in any server-rendered Jinja output.

    `show_token_login` hides the "Direct/script access instead" token
    form for a deployment that has Portal SSO configured - found
    confusing 2026-10-14: an ordinary AgentMesh user whose session timed
    out saw a raw "Access token" field with nothing telling them they
    don't have one, right next to the actual fix ("Return to the
    AgentMesh Portal"). Still shown (default True) for a genuinely
    standalone deployment with no Portal at all - see main.py's two call
    sites - since the token form is the *only* way to authenticate a
    browser there, not an alternative to a Portal login that doesn't
    exist. The `/login` POST route itself is unchanged either way -
    this only controls whether the HTML form is rendered."""
    template = _env().get_template("login.html.j2")
    return template.render(next_path=next_path, error=error, show_token_login=show_token_login)
