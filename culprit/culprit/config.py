"""Environment-driven configuration. Every value here has a safe default
for local/demo use; production deployment overrides via environment
variables only - nothing is hardcoded that would need a code change to
point at a different subscription, workspace, or Datadog org."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = os.environ.get("CULPRIT_DATABASE_URL", "sqlite:///culprit.db")
    log_analytics_workspace_id: str = os.environ.get("CULPRIT_LOG_ANALYTICS_WORKSPACE_ID", "")
    subscription_ids: tuple[str, ...] = tuple(
        s.strip() for s in os.environ.get("CULPRIT_SUBSCRIPTION_IDS", "").split(",") if s.strip()
    )
    rca_model: str = os.environ.get("CULPRIT_RCA_MODEL", "claude-opus-5")
    teams_webhook_url: str = os.environ.get("CULPRIT_TEAMS_WEBHOOK_URL", "")
    slack_webhook_url: str = os.environ.get("CULPRIT_SLACK_WEBHOOK_URL", "")
    # Only consulted by the scheduler/event-driven notify path (scheduler/cron.py)
    # - there's no inbound HTTP request there to build a report link from the
    # way /runs/live's route does (routes_runs.py::_report_url). Leave unset
    # to omit the "Open full report" link from those digests entirely rather
    # than guess at a URL. Include the reverse-proxy prefix if there is one,
    # e.g. "https://portal.local/culprit".
    public_url: str = os.environ.get("CULPRIT_PUBLIC_URL", "").rstrip("/")
    # Off by default - a deployment that already has an external scheduler
    # (a k8s CronJob, an Azure Function on a timer) triggering /runs/live
    # itself shouldn't also get an in-process one. See scheduler/cron.py
    # and main.py's lifespan handler.
    scheduler_enabled: bool = os.environ.get("CULPRIT_SCHEDULER_ENABLED", "false").lower() == "true"
    scheduled_cron: str = os.environ.get("CULPRIT_SCHEDULED_CRON", "0 4 * * *")
    preflight_interval_minutes: int = int(os.environ.get("CULPRIT_PREFLIGHT_INTERVAL_MINUTES", "60"))
    promotion_precision_threshold: float = float(os.environ.get("CULPRIT_PROMOTION_THRESHOLD", "0.95"))
    promotion_min_sample: int = int(os.environ.get("CULPRIT_PROMOTION_MIN_SAMPLE", "50"))
    scrub_network_and_pii: bool = os.environ.get("CULPRIT_SCRUB_PII", "false").lower() == "true"
    encryption_key: str = os.environ.get("CULPRIT_ENCRYPTION_KEY", "")
    api_token: str = os.environ.get("CULPRIT_API_TOKEN", "")
    # Same signing secret as Portal's SECRET_KEY (see portal/security.py's
    # own docstring: "all apps share the secret").
    # Lets an already-authenticated platform user launch straight into
    # Culprit instead of hitting a second, unrelated login wall - see
    # security/portal_jwt.py.
    portal_jwt_secret: str = os.environ.get("CULPRIT_PORTAL_JWT_SECRET", "")
    # The Portal API's own in-cluster address (not the public/proxied URL)
    # - used only server-to-server, to fetch which AI provider is active
    # platform-wide for the deep RCA agent (api/deps.py::get_rca_agent,
    # portal/api/routers/ai_providers.py::get_resolved_active_provider).
    # Blank (e.g. running Culprit standalone, no Portal deployed at all)
    # just means that lookup is skipped - same graceful-degradation shape
    # as every other optional integration here.
    portal_internal_url: str = os.environ.get("CULPRIT_PORTAL_INTERNAL_URL", "http://portal-api:8000").rstrip("/")
    # Where "Return to the AgentMesh Portal" / "Portal Home" links
    # (login.html.j2, base.html.j2) actually send a browser - the
    # *public*, browser-reachable Portal URL, unlike portal_internal_url
    # above (an in-cluster address nothing outside Docker can resolve).
    # Blank (the default) means "Portal lives at this same origin's site
    # root" - true for the intended nginx-proxied deployment shape
    # (root_path_middleware.py's own docstring: Culprit under /culprit/,
    # Portal's SPA as nginx's catch-all "/"), so a bare "/" is correct
    # there and nothing needs to change. Found broken 2026-10-14 on a
    # deployment reached directly on Culprit's own exposed port (bypassing
    # nginx entirely) - "/" there is Culprit's own site root, not Portal's,
    # and since that root also requires auth, clicking the button just
    # drew a silent 401 with no visible feedback. Set this explicitly on
    # any deployment where Culprit's own origin isn't also Portal's.
    portal_public_url: str = os.environ.get("CULPRIT_PORTAL_PUBLIC_URL", "")
    # Agent memory (see memory/store.py) - off by default, and a no-op even
    # when on unless the optional `culprit[memory]` extra (mem0ai +
    # sentence-transformers) is installed. Every write still goes only
    # through a confirmed verdict (routes_verdicts.py) - this flag decides
    # whether that write also lands in mem0, not what may write to it.
    memory_enabled: bool = os.environ.get("CULPRIT_MEMORY_ENABLED", "false").lower() == "true"
    # On-disk only (no server, no network) - Chroma's local persistent mode.
    # Relative paths resolve under the process's working directory, same as
    # CULPRIT_DATABASE_URL's sqlite:///culprit.db default.
    memory_chroma_path: str = os.environ.get("CULPRIT_MEMORY_CHROMA_PATH", "culprit_memory_db")
    # Local, on-disk sentence-transformers model - no API call, no data
    # leaves the host. Swapping this requires re-embedding everything
    # already stored (a different model means a different vector space).
    memory_embed_model: str = os.environ.get("CULPRIT_MEMORY_EMBED_MODEL", "multi-qa-MiniLM-L6-cos-v1")
    # On by default - preserves the existing dev/demo/test experience with
    # zero configuration. Set to false for any deployment a real stakeholder
    # or end user reaches directly (POST /runs/demo fabricates a synthetic
    # 312-machine fleet; a live system shouldn't expose a button that
    # conjures fake data). Gates both the Console page's "Demo scenario"
    # card and the route itself (api/routes_runs.py::trigger_demo_run
    # 404s, not just hides the button, when this is off) - found 2026-10-14,
    # same code either way, this is a deployment-config difference only.
    demo_enabled: bool = os.environ.get("CULPRIT_DEMO_ENABLED", "true").lower() == "true"
    # Off by default - this is the one flag in this file that gates code
    # which can mutate real infrastructure, not just read it. See
    # culprit/remediation/ and SECURITY.md's "Remediation execution" section.
    # Gates both the Fleet Report page's "Run remediation" button and the
    # POST /remediation/.../execute route itself (404s, not just hides the
    # button, when this is off - same demo_enabled precedent above).
    remediation_enabled: bool = os.environ.get("CULPRIT_REMEDIATION_ENABLED", "false").lower() == "true"


settings = Settings()
