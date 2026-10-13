# Culprit

**Every failed patch has a culprit. Find it in minutes, not days.**

Culprit is an autonomous agent that diagnoses *why* Azure Update Manager
patch deployments failed across a VM fleet, and prescribes what to do
about it - in minutes, unattended, at any fleet size. It reads Azure
(Resource Graph, Activity Log, Log Analytics), the guest OS (Windows and
Linux, via allow-listed read-only commands), and Datadog, collapses
hundreds of failures into a handful of distinct root causes, settles the
unambiguous ones with a deterministic rule engine, and hands the
genuinely ambiguous tail to Claude for deep reasoning - never the other
way around.

This is **Phase 1**: analysis and remediation guidance. It is read-only by
construction - the credential it runs as has no write permission to any
resource, anywhere. See [`SECURITY.md`](SECURITY.md) for exactly what that
means and why. Phase 2 (automated remediation) is a separate, later
decision gated on measured per-cause-family precision - see
[`ARCHITECTURE.md`](ARCHITECTURE.md#the-phase-2-gate).

The design rationale for every choice below - why cluster before
diagnosing, why rules run before the model, why the RCA output is
schema-enforced - is in the original proposal this repository implements.
If you don't have that document, [`ARCHITECTURE.md`](ARCHITECTURE.md) covers
the same ground against the actual code.

## What's real here, and what needs credentials

Everything in this repository is real, working code - nothing is a stub
pretending to be finished. What differs by module is whether it needs
external credentials to *run against a live environment*:

| Layer | Status |
|---|---|
| Fingerprinting, clustering, rule engine, advisor, precision gate | Fully self-contained. No credentials of any kind. Exercised end-to-end by the test suite. |
| Guest log parsers (`collectors/guest_linux.py`, `guest_windows.py`) | Pure functions over real dpkg/apt/yum/CBS/WindowsUpdate log text - unit-tested directly, no VM needed. |
| Azure / Datadog collectors | Real SDK calls (`azure-mgmt-resourcegraph`, `azure-monitor-query`, `azure-mgmt-compute`, `datadog-api-client`), correctly shaped against each service's actual API - but they need a real subscription / workspace / Datadog org to call against. |
| Deep RCA agent (`pipeline/rca_agent.py`) | Real multi-provider LLM integration (Anthropic by default, or any provider in `shared/src/llm/catalog.py` - OpenAI, Azure OpenAI, Gemini, Grok, Qwen, DeepSeek, Ollama, LM Studio) via strict tool-use / schema-enforced output. Which one is active is a platform-wide admin setting on the AgentMesh Portal's Admin → AI Providers screen (`portal/api/routers/ai_providers.py`) - unset there, this falls back to `ANTHROPIC_API_KEY` (or an `ant auth login` profile), then to a clearly-labeled scripted stand-in (see below). |
| API, DB, reporting, scheduler | Fully self-contained. SQLite by default; point at Postgres for production. |
| Azure/Datadog **connection settings** (`/settings` screen) | Fully self-contained - a real settings UI (encrypted-at-rest storage, masked GET responses, a genuine "Test connection" that calls the provider) with no credentials of its own required to use it. What it configures (a real subscription, a real Datadog org) is what needs credentials, not the screen itself. |
| Agent memory (`memory/`) | Real mem0 integration, verified end to end against a live mem0/Chroma/sentence-transformers install (remember, semantic recall, forget-on-wrong-verdict) - but off by default and a graceful no-op without `pip install 'culprit[memory]'`. Self-hosted only: on-disk Chroma, a local embedder, no data leaves the host. See `culprit/memory/__init__.py` and RUNBOOK.md §8. |

**The demo and the entire test suite run with zero credentials.** Where a
live call would be needed, either a fixture stands in (collectors) or a
scripted, clearly-logged fallback stands in (the RCA agent) - see
`culprit/demo/scripted_rca.py`. Set `ANTHROPIC_API_KEY` and the demo
switches to a real `claude-opus-5` call automatically; nothing else
changes.

## Configuring Azure and Datadog access

The demo scenario (`/runs/demo`, and `python -m culprit.demo.run_demo`)
needs none of this - it's entirely synthetic. To have Culprit diagnose
*real* patch failures, open **`/settings`** (linked from the console page)
and fill in:

- **Azure**: subscription id(s), the Log Analytics workspace id, and
  either nothing (falls back to a managed identity via
  `DefaultAzureCredential` - only works if this process is actually
  running as one, i.e. inside Azure) or a service principal's tenant/
  client id and secret (works anywhere, including this demo host).
- **Datadog**: site, API key, app key.

Each has a **Test connection** button that makes a real, read-only call
(an Azure token fetch + a trivial Resource Graph query; Datadog's own
`AuthenticationApi.validate()`) and reports exactly what happened. Secrets
are encrypted at rest (Fernet, keyed by `CULPRIT_ENCRYPTION_KEY`) and are
never echoed back by any GET - the screen only ever reports whether one is
configured.

Once both are saved, **`POST /runs/live`** (or the "Run live analysis"
trigger on the Console page) discovers every machine with a non-succeeded
patch result in a given time window (default: the last 24h) via Resource
Graph, collects real evidence for each, and runs it through the exact
same pipeline the demo does. See `culprit/api/routes_settings.py` and
`culprit/pipeline/discovery.py`. To run this automatically on a recurring
schedule instead of triggering it by hand, use the "Scheduled runs" card
on `/settings` - see "Scheduling" in [`RUNBOOK.md`](RUNBOOK.md).

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"

pytest                          # 204 tests, all offline, ~2s (3 need pip install -e ".[azure]" to run instead of skip)

python -m culprit.demo.run_demo # runs the exact 312/47/6-cluster scenario
                                 # from the proposal end to end, writes
                                 # culprit/demo/fleet_report.html
```

Set `ANTHROPIC_API_KEY` before the last command to have the two clusters
the rule engine can't settle (window-exhaustion, and the deliberately
sparse "unresolved" case) go to a real `claude-opus-5` call instead of the
scripted stand-in.

Every route above requires `CULPRIT_API_TOKEN` if it's set (a cookie from
`/login` for a browser, `Authorization: Bearer <token>` for scripts) -
unset, there's no authentication at all, which is fine for the offline
demo and is exactly what keeps it working with zero configuration, but
set a real one before this ever holds real credentials. See SECURITY.md.

To run the API:

```bash
uvicorn culprit.api.main:app --reload
# GET  /                      - console (HTML): "Run patch-failure analysis" button
# GET  /runs.html             - every run Culprit has diagnosed, most recent first (which update job, when, machines/failed/causes)
# GET  /settings              - Azure/Datadog connection settings (HTML)
# GET  /settings/azure, /settings/datadog     - current view (secrets masked)
# PUT  /settings/azure, /settings/datadog     - save
# POST /settings/azure/test, /settings/datadog/test  - real connection test
# GET/PUT /settings/schedule   - recurring live-run config (cron, window, scope) - see Scheduling below
# POST /runs/demo             - trigger the demo scenario, get a FleetReport back
# POST /runs/live             - discover + diagnose real failed machines (needs /settings configured)
# GET  /runs/{run_id}/report - the same report, JSON
# GET  /runs/{run_id}/report.html
# GET  /runs/{run_id}/machines/{vm_name}.html  - one machine's own patch outcome (status, error, failed KB/package) plus its deviation from its cluster
# POST /verdicts              - submit an engineer verdict on an RCA card
# GET  /precision, /precision.html  - per-cause-family precision + Phase 2 gate status (JSON/HTML)
# GET  /preflight              - the latest pre-flight scan's findings (see Scheduling in RUNBOOK.md)
# POST /chat                   - "why did vm-x fail?" / "what's failing across the fleet?" /
#                                 "which machines will fail next?" (reads the pre-flight scan)
# POST /webhooks/event-grid    - Event Grid receiver (validation handshake + dispatches a real run)
```

Set `CULPRIT_SCHEDULER_ENABLED=true` so this process also runs the scheduled
and pre-flight autonomy modes in-process; the recurring schedule itself
(cron, window, scope, and the on/off toggle) is then edited live from the
"Scheduled runs" card on `/settings`, no redeploy needed - see "Scheduling"
in [`RUNBOOK.md`](RUNBOOK.md).

Or with Docker Compose (Postgres + API):

```bash
cp .env.example .env   # fill in what you have; every value has a safe default
docker compose up --build
```

## Repository layout

```
culprit/
  models/         domain models - Evidence, PatchRun, Cluster, RCAResult, Verdict, taxonomy
  collectors/     Azure / guest OS / Datadog collectors (real SDK shapes)
  pipeline/       normalize -> fingerprint/cluster -> rules -> rca_agent -> advisor -> orchestrator
  retrieval/      lightweight RAG over vendor docs + this org's resolved-incident history
  memory/         mem0-backed episodic memory (optional - pip install 'culprit[memory]')
  db/             SQLAlchemy persistence (SQLite by default, Postgres-ready)
  reporting/      fleet report model, HTML rendering, Teams/Slack notification
  api/            FastAPI app
  scheduler/      cron (scheduled + pre-flight) and Event Grid webhook receiver
  security/       RBAC role definition, secret/PII scrubbing
  demo/           the exact proposal scenario + scripted RCA fallback + run_demo.py
tests/            204 tests, fully offline
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for how each module maps to the
pipeline design, [`SECURITY.md`](SECURITY.md) for the RBAC role and data
handling, and [`RUNBOOK.md`](RUNBOOK.md) for wiring this up against a real
subscription.

## What's deliberately out of scope for this pass

- **A React dashboard.** The API is CORS-ready for one, and the JSON
  shapes (`FleetReport`, per-cluster entries) are the contract a frontend
  would consume - but the deliverable here is the working HTML report
  (`reporting/render.py`) plus the API, not a full SPA.
- **Container and database patching.** The collector/evidence model is
  source-pluggable by design (proposal's stated intent), but only VM
  collectors are implemented.
- **A vector-database-backed retrieval store for vendor documentation.**
  `retrieval/store.py` (the small, fixed seed set of vendor docs) stays a
  real, working, dependency-light TF-IDF-style store on purpose - it
  doesn't grow and doesn't need real embeddings to search well. Confirmed
  RCAs *are* on a real vector store now, optionally - see `memory/`.
- **Phase 2 (automated remediation).** Deliberately not started - it's a
  later decision, gated on the precision numbers this Phase 1 build
  produces.
