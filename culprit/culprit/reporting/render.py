"""Render a FleetReport to HTML."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from culprit.models.report import FleetReport

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env() -> Environment:
    # remediation_enabled is a Jinja *global*, not a per-call render
    # kwarg, specifically so base.html.j2's shared nav (extended by every
    # page) can gate the "Remediation log" link on it without threading
    # a new parameter through every single render_*_html function and
    # call site - every template already goes through this one function,
    # so this is the one place that needs to know about the flag at all.
    # supported_action_families/promotion_threshold/promotion_min_sample
    # are static, process-wide config too (not per-request data like
    # family_precision, which stays an explicit render parameter) - same
    # reasoning, same treatment.
    from culprit.config import settings
    from culprit.models.remediation import SUPPORTED_ACTIONS

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    env.globals["remediation_enabled"] = settings.remediation_enabled
    env.globals["supported_action_families"] = SUPPORTED_ACTIONS
    env.globals["promotion_threshold"] = settings.promotion_precision_threshold
    env.globals["promotion_min_sample"] = settings.promotion_min_sample
    return env


def render_fleet_report_html(report: FleetReport, family_precision=None) -> str:
    """`family_precision` (dict[CauseFamily, FamilyPrecision]) is a
    render-only input, deliberately kept off `FleetReport` itself (that
    model is also returned as plain JSON from GET /runs/{run_id}/report) -
    same "UI-only data stays a render parameter, not a model field"
    convention render_console_html already uses for `demo_enabled`. Used
    to decide what the "Run remediation" control under each cluster's
    Phase 2 badge shows once a family clears the gate - see
    routes_runs.py::get_report_html for where it's computed.
    `remediation_enabled` itself is a Jinja global (see _env()), not
    passed here - whether the button exists at all vs. not rendering is
    gated in the template directly."""
    template = _env().get_template("fleet_report.html.j2")
    # This page lives two levels below the app root (runs/{id}/report.html),
    # unlike every other page here - nav_prefix corrects the shared sidebar's
    # otherwise-root-relative links (base.html.j2) so they still resolve
    # correctly from this depth.
    return template.render(report=report, active="console", nav_prefix="../../", family_precision=family_precision or {})


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


def render_login_html(next_path: str = "/", error: str = "") -> str:
    """The shared-token sign-in page (culprit/api/auth_middleware.py) -
    doesn't extend base.html.j2, since there's nothing to put in the
    sidebar for someone who isn't authenticated yet. `next_path` and
    `error` are plain Jinja variables, autoescaped like every other
    template here - the XSS finding from review was in settings.html.j2's
    client-side JS, not in any server-rendered Jinja output."""
    template = _env().get_template("login.html.j2")
    return template.render(next_path=next_path, error=error)
