# Runbook: wiring Culprit against a real environment

This repository runs the full pipeline offline (see README). This is what
Phase 0/1 actually needs to point it at a real subscription.

## 1. Azure

1. Create the custom role from `culprit/security/rbac/culprit-reader-role.json`
   (replace `<subscription-id>` in `AssignableScopes`):
   ```bash
   az role definition create --role-definition culprit/security/rbac/culprit-reader-role.json
   ```
2. Create a managed identity for wherever Culprit runs (a container app,
   an Azure Function, a VM) and assign it the **Culprit Reader** role at
   the subscription scope. Do not also assign Contributor.
3. Enter the subscription id(s) and Log Analytics workspace id on the
   **`/settings` screen** (this is the primary way now - see "Connection
   settings" below). Leave tenant/client/secret blank to use the managed
   identity from step 2 via `DefaultAzureCredential`; fill them in for a
   service principal instead (needed on any host that isn't itself
   running in Azure, which is most demo/dev hosts). `CULPRIT_SUBSCRIPTION_IDS`
   / `CULPRIT_LOG_ANALYTICS_WORKSPACE_ID` env vars (`.env.example`) still
   work as a fallback default for `culprit/config.py`, but nothing reads
   them once the settings screen has values saved.
4. Install the optional Azure extras: `pip install -e ".[azure]"`.

## 2. Datadog

Enter the site and either a Personal Access Token or an API key/app key
pair on the **`/settings` screen** - the screen's "Authentication method"
toggle picks which. The API key needs read scope only (metrics, monitors,
logs read) - no write scope is used anywhere in
`collectors/datadog_collector.py`. A Personal Access Token is Datadog's
newer alternative, documented for v2 API calls (confirmed to work for this
app's v2 Logs collection); v1 compatibility for the Metrics/Monitors
collection this app also does isn't documented either way by Datadog as of
2026-10, and PATs are a Preview feature on Datadog's side - see
`collectors/datadog_auth.py`'s docstring before relying on one in
production. The standard `DD_API_KEY`/`DD_APP_KEY`/`DD_SITE` env vars still
work as a fallback if nothing is saved on the settings screen (the Datadog
SDK's own env resolution - there's no PAT equivalent env var). Install
with `pip install -e ".[datadog]"`.

## Connection settings (the `/settings` screen)

Both of the above can be entered through **`GET /settings`** (a plain
HTML page - linked from the console at `/`) instead of environment
variables: subscription ids, workspace id, an optional service-principal
tenant/client/secret (or a managed identity, if neither is given), and
the Datadog site plus either a Personal Access Token or an API key/app
key pair. Each field group has a **Test connection** button that makes a
real, read-only call and reports what happened, and everything is stored
encrypted at rest
(Fernet, keyed by `CULPRIT_ENCRYPTION_KEY` - set this in any real
deployment; there's an insecure dev-only default so the screen still
works with zero configuration). See `culprit/api/routes_settings.py`,
`culprit/db/repository.py` (the encrypt/decrypt boundary), and
`culprit/security/crypto.py`.

Once both are saved, **`POST /runs/live`** (or the "Run live analysis"
button on the same page) runs the real pipeline: `culprit/pipeline/discovery.py`
finds every machine with a non-succeeded patch result in the window via
Resource Graph, `culprit/pipeline/collection.py::collect_all` gathers
real evidence for each, and the rest of the pipeline runs unchanged from
the demo. `culprit/pipeline/live_run.py::execute_live_run` is this exact
discover -> collect -> diagnose path shared by all three real triggers -
`POST /runs/live` (ad hoc), `scheduled_cycle` (scheduled, below), and the
Event Grid handler (event-driven) - so there's no separate "which
machines are in scope" wiring left to write for the scheduled path; it
already reuses the same query.

## 3. Claude / Anthropic (or another provider)

Which model the deep RCA agent calls is a platform-wide setting on the AgentMesh Portal's
Admin → AI Providers screen (`portal/api/routers/ai_providers.py`) - not a Culprit env var
first, since it's shared with any other app that needs an LLM call too. See "AI Providers" in
[docs/SETUP.md](../docs/SETUP.md) for the full picture, including why there's deliberately no
default provider.

If that screen is never touched (or Culprit is running standalone with no Portal deployed),
this falls back to the original behavior: set `ANTHROPIC_API_KEY` (or run `ant auth login` and
leave it unset - the SDK picks up the active profile automatically). `CULPRIT_RCA_MODEL`
defaults to `claude-opus-5`; override only if you have a specific reason to use a different
model.

## 4. Database

Point `CULPRIT_DATABASE_URL` at Postgres for anything beyond a single-
process demo:
```
CULPRIT_DATABASE_URL=postgresql+psycopg://user:pass@host:5432/culprit
```
`docker-compose.yml` brings up a local Postgres for you. Nothing in
`culprit/db/` needs changing - it's plain SQLAlchemy against whatever URL
you give it.

## 5. Scheduling

Set `CULPRIT_SCHEDULER_ENABLED=true` (`.env.example`) and the app starts
an in-process APScheduler on startup (`culprit/api/main.py`'s lifespan
handler, via `culprit/scheduler/cron.py::build_scheduler`) with two jobs:

- **`scheduled_cycle`** - fires on `CULPRIT_SCHEDULED_CRON` (default
  `0 4 * * *`; set it to shortly after your maintenance window closes).
  Reads whatever's saved on **`/settings`** at fire time (not a
  subscription id baked into a job argument), then runs the exact same
  discover -> collect -> diagnose path as `POST /runs/live`
  (`culprit/pipeline/live_run.py::execute_live_run`) - same "everything
  that failed in the window" approximation described above, just
  triggered by cron instead of a request.
- **`pre_flight_check`** - fires every `CULPRIT_PREFLIGHT_INTERVAL_MINUTES`
  (default 60). Enumerates every machine in the configured subscription(s)
  via `pipeline/discovery.py::discover_all_machines` (follows Resource
  Graph's own `skip_token` across pages, so a fleet larger than one page -
  1000 machines - is still scanned in full, not truncated), collects the
  same evidence the rule engine reads post-hoc, and persists any rule hit
  as a pre-flight warning (`GET /preflight`, and the "which machines will
  fail next" chat query). No deep RCA call in this path - it's
  rule-engine-only by design, so it's cheap enough to run continuously.

Both jobs are no-ops (logged, not raised) when nothing is configured on
`/settings` yet, and neither one crashes the scheduler if a single run
fails - check the app logs for `Scheduled cycle failed` / `Pre-flight
check failed` if a cycle silently didn't produce a report.

Off by default: a deployment that already has an external scheduler (a
k8s CronJob, an Azure Function on a timer) calling `POST /runs/live`
itself shouldn't also get an in-process one.

## 6. Event-driven trigger

Read the caveat in `culprit/scheduler/events.py` before wiring this up -
Azure Update Manager doesn't publish a documented Event Grid system topic
for "run completed" as of this writing. Pick one:

- **Action Group webhook** on an Activity Log alert scoped to
  `Microsoft.Maintenance/applyUpdates` completions - the more standard
  path, no custom polling code needed.
- **A small Function/Logic App poller** watching `maintenanceresources`
  for a run leaving `InProgress`, posting to `/webhooks/event-grid` itself.

Either way, register the endpoint as an Event Grid subscription (or plain
webhook) pointed at `POST /webhooks/event-grid` - the handler implements
the subscription-validation handshake, then dispatches the same
discover -> collect -> diagnose path `scheduled_cycle` uses as a
background task (so the webhook itself responds immediately, before the
run actually completes - Event Grid expects a fast response and retries
on a timeout).

## 7. Notifications

Set `CULPRIT_TEAMS_WEBHOOK_URL` and/or `CULPRIT_SLACK_WEBHOOK_URL` to a
real Incoming Webhook URL and every completed run posts a digest
automatically - `POST /runs/demo`, `POST /runs/live`, `scheduled_cycle`,
and the event-driven trigger all call `reporting/notify.py` themselves
once the pipeline finishes; nothing extra to wire up. A failed webhook
post is logged and swallowed, never fails the run that already succeeded.

The digest's "Open full report" link needs `CULPRIT_PUBLIC_URL` set to
this app's externally-reachable URL (reverse-proxy prefix included, e.g.
`https://portal.local/culprit`) - only the scheduler/event-driven path
needs this env var, since `POST /runs/live` already has a real inbound
request to build the link from.

## 8. Agent memory

`pip install 'culprit[memory]'` (mem0ai + sentence-transformers - not in the
base image, so this is opt-in) then set `CULPRIT_MEMORY_ENABLED=true`. Every
confirmed-correct verdict (`POST /verdicts` with `"verdict": "correct"`)
becomes a memory the deep RCA agent's prompt includes as evidence for the
next similar cluster; a later "wrong" verdict on the same recurring cause
forgets it. Off by default, and a graceful no-op (falls back to the plain
vendor-doc retrieval store, logged once) if the extra isn't installed - see
`culprit/memory/__init__.py` for what this is and, as importantly, what was
deliberately left out of the port from the platform's own agent-memory
design (`shared/src/memory/` on the `test` branch): no generic outcome
ledger (Culprit's own `Verdict`/`VerdictRecord` table already is one), no
facts/lessons/preferences/graph memory/MCP server - none of those map onto
what a single RCA agent with a rule engine and a precision gate already
does in code.

Self-hosted only, same principle as the original design: `CULPRIT_MEMORY_CHROMA_PATH`
is an on-disk Chroma instance (no server, nothing shared with any other
app), and `CULPRIT_MEMORY_EMBED_MODEL` is a local sentence-transformers
model (no API call). `memory/store.py::assert_self_hosted` refuses a config
that would route around either. The one component that DOES call a cloud
API is the placeholder LLM provider mem0 wants configured
(`ANTHROPIC_API_KEY`, reused from the deep RCA agent's own credential) -
it's never actually invoked, since every write here uses mem0's `infer=False`
mode (store exactly this text, no model-driven extraction); Culprit has no
per-user preference surface that would need mem0's `infer=True`, so that
entire code path - and the prompt-injection surface it would open - simply
isn't built here.

Verified end to end against a real mem0/Chroma/sentence-transformers
install before this shipped (remember, real semantic recall, cause-family
filtering, forget-on-wrong-verdict, all through the actual API routes) -
see `culprit/tests/test_memory.py` for the equivalent coverage against a
fake mem0 client, which is what actually runs in CI (the real stack is a
heavy optional extra, not something the test suite depends on).

## 9. Phase 0 - before any of the above matters

Ingest 2-3 historical patch cycles from Log Analytics / Resource Graph
directly (no need to run the live pipeline for this) and check:

- Do guest logs (dpkg.log, CBS.log, WindowsUpdate.log) still exist by the
  time you'd collect them, or has retention already rotated them out? If
  short retention is a problem, the event-driven trigger (fires within
  minutes of window close) matters more than the scheduled one.
- Does the failure taxonomy in `models/taxonomy.py` actually cover what
  this estate's failures look like? Extend `CauseFamily` and
  `pipeline/rules.py` before Phase 1b if not - this is expected, not a
  sign something's wrong.
- Is Datadog agent coverage good enough on these machines for the
  precondition metrics (`collectors/datadog_collector.py`'s
  `_PRECONDITION_METRIC_QUERIES`) to mean anything? If most machines don't
  report `system.disk.in_use`, the capacity-family rules and the deep RCA
  agent alike will be working from partial evidence - fix the telemetry
  gap before trusting the RCA output for that machine class.

## Health check

`GET /health` on the FastAPI app. There is no separate health check for
the scheduler process - monitor it the way you'd monitor any APScheduler-
based worker (process liveness + the `RunRecord.stage` column in the DB
not getting stuck on the same run for longer than a cycle should take).
