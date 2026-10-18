"""Render a FleetReport to HTML."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from culprit.models.installation_report import InstallationReport
from culprit.models.report import FleetReport

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env(tz_name: str = "UTC") -> Environment:
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
    from culprit.reporting.timezone_display import register_localtime_filter

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
    register_localtime_filter(env, tz_name)
    return env


def _cluster_date_ranges(report: FleetReport, tz_name: str = "UTC") -> dict[str, tuple]:
    """Per-cluster (earliest, latest) patch date across its own members,
    from data already collected and persisted (PatchOutcome.started_at,
    joined into FleetReport.machine_rows by _load_fleet_report_core) - no
    new Azure query needed.

    Why this exists: a live/scheduled run's discovery window is a time-
    window heuristic standing in for "one maintenance run" (pipeline/
    discovery.py's own docstring), not a resolved Azure maintenance-run
    boundary - a wide window (the scheduled default is 8 days; an ad hoc
    run can be configured up to 30) routinely sweeps machines from
    several real maintenance executions into one Culprit run. Two cluster
    cards can end up with the same RCA title for either reason: they're
    the same recurring cause from two different maintenance cycles the
    window happened to span, or they're genuinely different structural
    causes (fingerprint.py clusters on error code/OS/failing target/
    preconditions, never on when something failed, never on the title
    text) that just read similarly once summarized into prose. A reported
    team confusion ("why are there separate sections for the same
    issue?") is resolved either way by showing each card's own date range
    - either it visibly differs (confirming "different cycle, not a
    duplicate"), or it doesn't (a signal to look at cause_family/evidence
    more closely instead, not a duplicate bug to merge away)."""
    from culprit.reporting.timezone_display import localize_date

    ranges: dict[str, tuple] = {}
    by_cluster: dict[str, list] = {}
    for row in report.machine_rows:
        if row.outcome and row.outcome.started_at:
            by_cluster.setdefault(row.cluster_id, []).append(localize_date(row.outcome.started_at, tz_name))
    for cluster_id, dates in by_cluster.items():
        ranges[cluster_id] = (min(dates), max(dates))
    return ranges


def render_fleet_report_html(
    report: FleetReport, family_precision=None, promotion_threshold: float = 0.95, promotion_min_sample: int = 50,
    smtp_configured: bool = False, default_recipients: list | None = None, installation_report_available: bool = False,
    tz_name: str = "UTC",
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
    from culprit.reporting.evidence_gaps import parse_evidence_gaps

    template = _env(tz_name).get_template("fleet_report.html.j2")
    missing_evidence_by_cluster = {
        entry.cluster.cluster_id: parse_evidence_gaps(entry.result.missing_evidence)
        for entry in report.entries if entry.result.missing_evidence
    }
    cluster_date_ranges = _cluster_date_ranges(report, tz_name)
    # This page lives two levels below the app root (runs/{id}/report.html),
    # unlike every other page here - nav_prefix corrects the shared sidebar's
    # otherwise-root-relative links (base.html.j2) so they still resolve
    # correctly from this depth.
    return template.render(
        report=report, active="console", nav_prefix="../../", family_precision=family_precision or {},
        cluster_date_ranges=cluster_date_ranges,
        promotion_threshold=promotion_threshold, promotion_min_sample=promotion_min_sample,
        smtp_configured=smtp_configured, default_recipients=default_recipients or [],
        installation_report_available=installation_report_available,
        missing_evidence_by_cluster=missing_evidence_by_cluster,
    )


def render_installation_report_html(report: InstallationReport, tz_name: str = "UTC") -> str:
    """The Azure Update Manager-style full-fleet view
    (models/installation_report.py) - lives at the same depth as
    report.html (runs/{id}/installation-report.html), same nav_prefix."""
    template = _env(tz_name).get_template("installation_report.html.j2")
    return template.render(report=report, active="console", nav_prefix="../../")


def render_runs_html(runs, demo_enabled: bool = True, tz_name: str = "UTC") -> str:
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
    template = _env(tz_name).get_template("runs.html.j2")
    distinct_triggers = sorted({r.trigger_mode for r in runs})
    distinct_stages = sorted({r.stage for r in runs})
    return template.render(
        runs=runs, active="runs", demo_enabled=demo_enabled,
        distinct_triggers=distinct_triggers, distinct_stages=distinct_stages,
    )


def _trend_chart_geometry(trend, tz_name: str = "UTC", width: int = 300, height: int = 72, pad_x: float = 4, pad_y: float = 8):
    """SVG coordinates for the Console dashboard's compliance trend line.
    Computed here, not in the template - scaling the line to its own
    data's min/max (not a fixed 0-100 axis, which would flatten real-world
    compliance% variation most runs never leave the 80-100 band in to a
    near-flat line) is a float computation across every point, not a
    single Jinja filter expression."""
    from culprit.reporting.timezone_display import localize_date

    values = [p.compliance_pct for p in trend]
    lo, hi = min(values), max(values)
    if hi == lo:  # every point identical - avoid a divide by zero, draw a flat middle line instead
        lo, hi = lo - 1, hi + 1

    n = len(trend)
    points = []
    for i, p in enumerate(trend):
        x = width / 2 if n == 1 else pad_x + (i / (n - 1)) * (width - 2 * pad_x)
        y = pad_y + (1 - (p.compliance_pct - lo) / (hi - lo)) * (height - 2 * pad_y)
        points.append({"x": round(x, 1), "y": round(y, 1), "pct": p.compliance_pct, "date": localize_date(p.started_at, tz_name).isoformat()})

    return {
        "width": width,
        "height": height,
        "points": points,
        "polyline": " ".join(f"{pt['x']},{pt['y']}" for pt in points),
    }


def render_console_html(demo_enabled: bool = True, dashboard=None, tz_name: str = "UTC") -> str:
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
    trend_chart = _trend_chart_geometry(dashboard.compliance_trend, tz_name) if len(dashboard.compliance_trend) >= 2 else None

    template = _env(tz_name).get_template("console.html.j2")
    return template.render(active="console", demo_enabled=demo_enabled, dashboard=dashboard, trend_chart=trend_chart)


def render_settings_html() -> str:
    """The Azure/Datadog connection settings screen - reads and writes
    culprit/api/routes_settings.py entirely client-side via fetch()."""
    template = _env().get_template("settings.html.j2")
    return template.render(active="settings")


def render_machine_html(
    cluster, member, result, outcome=None, collection_gaps=None, patch_extension_status=None, timeline=None,
    checks_performed=None, tz_name: str = "UTC",
) -> str:
    """The third report altitude (proposal Section 8): one machine's own
    timeline deviation from its cluster's representative, plus its own
    `PatchOutcome` (status, error, failed KB/package) when this run saved
    one - see MachineOutcomeRecord; `outcome` is None for runs diagnosed
    before that existed, not an error. Lives three levels below the app
    root (runs/{id}/machines/{vm_id}.html), hence the deeper nav_prefix -
    see render_fleet_report_html's comment.

    `patch_extension_status` (collectors/patch_extension_status.py's own
    structured findings, persisted on MachineOutcomeRecord) is evidence
    that WAS collected - the guest patch extension's own account of what
    happened - unlike `collection_gaps`, which is evidence that could NOT
    be collected. Kept as a separate card for exactly that reason; see
    extension_status_view.py for the display mapping.

    `outcome.error_details` (Azure's own `ApiError.details[]`, see
    azure_error_view.py) is the control-plane equivalent - evidence Azure
    itself reported, independent of guest reachability - so it gets its
    own card too rather than being folded into either of the above.

    `rca_missing_evidence` (`result.missing_evidence`) is a third,
    distinct thing from both of the above - the RCA agent's own "here's
    what I'd need to be more confident" statement, not evidence that
    failed to collect (`collection_gaps`) or evidence that WAS collected
    (`patch_extension_status`/`outcome.error_details`). Found missing
    entirely from this page 2026-10-16 (the user's own screenshot of a
    15%-confidence machine showed nothing explaining what was thin about
    it) even though `result` already carries it - reuses the same
    parse_evidence_gaps/evidence_gap_card the fleet report's own
    equivalent section already uses, same display, same data.

    `timeline` (MachineOutcomeRecord.timeline_json, a capped slice of
    `EvidenceBundle.timeline` persisted by save_machine_outcomes - added
    2026-10-18) is the raw evidence the RCA agent's prompt was actually
    built from, shown here for the first time so a human reviewer can see
    the same thing the model saw, not just its conclusion - see
    evidence_timeline_view.py for the display mapping. None for runs
    diagnosed before this column existed, same as patch_extension_status.

    `checks_performed` (MachineOutcomeRecord.checks_performed_json, from
    `EvidenceBundle.checks_performed` - added 2026-10-19) is the plain list
    of checks genuinely attempted this run regardless of outcome. Shown as
    its own card rather than cross-matched against `rca_missing_evidence`
    text (deliberately not attempted: fuzzy-matching free-text evidence-gap
    prose against a fixed label list is brittle and risks a false "this
    gap is actually covered" suppression) - a human reviewer cross-checks
    the two cards themselves, same as they already do for the sibling
    evidence/gap cards above."""
    from culprit.reporting.azure_error_view import build_azure_error_views
    from culprit.reporting.evidence_gaps import parse_evidence_gaps
    from culprit.reporting.evidence_timeline_view import build_timeline_views
    from culprit.reporting.extension_status_view import build_extension_finding_views

    template = _env(tz_name).get_template("machine.html.j2")
    return template.render(
        cluster=cluster, member=member, result=result, outcome=outcome,
        evidence_gaps=parse_evidence_gaps(collection_gaps or []),
        extension_findings=build_extension_finding_views(patch_extension_status or []),
        azure_error_details=build_azure_error_views(outcome.error_details if outcome else []),
        rca_missing_evidence=parse_evidence_gaps(result.missing_evidence if result else []),
        evidence_timeline=build_timeline_views(timeline or []),
        checks_performed=checks_performed or [],
        active="console", nav_prefix="../../../",
    )


def render_precision_html(precision: dict) -> str:
    """The Phase 2 promotion gate (proposal Section 11), rendered - per-
    family precision, sample size, and whether each family currently
    clears the promotion bar."""
    template = _env().get_template("precision.html.j2")
    return template.render(active="precision", precision=precision)


def render_remediation_log_html(records, tz_name: str = "UTC") -> str:
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
    template = _env(tz_name).get_template("remediation_log.html.j2")
    return template.render(active="remediation", records=records, nav_prefix="../")


def render_email_report_html(report: FleetReport, top_entries: list, report_url: str | None, note: str, requested_by: str, tz_name: str = "UTC") -> str:
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
    template = _env(tz_name).get_template("email_report.html.j2")
    return template.render(
        report=report, top_entries=top_entries, report_url=report_url, note=note, requested_by=requested_by,
        cluster_date_ranges=_cluster_date_ranges(report, tz_name),
    )


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
