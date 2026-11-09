# Culprit serverless (Azure Durable Functions)

The Durable Functions port of Culprit's pipeline described in the
"Culprit Serverless Architecture Proposal" doc (2026-11-10). This
directory is the application code; `culprit/infra/main.bicep` is the
target infrastructure.

## What this is

- `function_app.py` - the 4 trigger bindings (Timer x2, HTTP, Event Grid).
- `orchestrators.py` - `pipeline_orchestrator` (the main discover/collect/
  diagnose/persist/notify sequence) and `diagnose_cluster_orchestrator`
  (a per-cluster sub-orchestration for the conditional rule-engine/deep-
  RCA/recollect/advise chain).
- `activities.py` - the actual work, each activity a thin wrapper calling
  straight into the existing `culprit/pipeline/`, `culprit/collectors/`,
  `culprit/db/` code - nothing in those modules changed except one small,
  behavior-preserving refactor (`pipeline/collection.py::collect_one_machine`
  extracted from a closure to a top-level function, so both this port and
  the existing Docker deployment call the identical per-machine logic).
- `serialization.py` - the handful of dict<->Pydantic/dataclass
  (de)serializers Durable Functions' JSON-only activity boundary needs.
- `Dockerfile` - a custom-container image for the Function App, built from
  the repo root exactly like `culprit/Dockerfile`.
- `host.json`, `local.settings.json.example` - standard Functions config.

## What's been verified, and how

- **The orchestrator control-flow logic is genuinely unit-tested**, not
  just written and trusted: `tests/test_serverless_orchestrators.py`
  drives both orchestrators as plain Python generators (Microsoft's own
  documented pattern for testing Durable Functions orchestrators - no
  live Functions host or Azure Storage emulator needed, since an
  orchestrator is deterministic code that only ever yields activity
  calls). 14 tests, including one that specifically guards against a
  real regression class: a cluster's recollected representative bundle
  must reach both the second deep-RCA call *and* persistence, not just
  the RCA call while the stale pre-recollection bundle silently gets
  persisted (the exact bug `pipeline/orchestrator.py::Pipeline.run`'s own
  docstring documents fixing for the Docker deployment on 2026-10-19).
  That test was sabotage-proven: temporarily reverted the fix, confirmed
  the test fails, restored it.
- **Serialization is verified against real model instances**
  (`tests/test_serverless_serialization.py`), not just "the function
  exists" - round-tripping a real `EvidenceBundle`/`Cluster`/`RCAResult`/
  `PatchRun`/`CollectionResult` through `.model_dump(mode="json")` and
  back.
- **The whole module tree imports cleanly** against the real `culprit`
  package (`python -c "import culprit.serverless.function_app"`),
  registering all 15 functions (4 triggers + 2 orchestrators + 9
  activities) with no import errors.
- **Every Durable Functions / Azure Functions API used here was checked
  against the installed `azure-functions`/`azure-functions-durable`
  packages directly** (`DFApp`, `Blueprint`, `activity_trigger`,
  `orchestration_trigger`, `call_activity`, `call_sub_orchestrator`,
  `task_all`, `durable_client_input`, `event_grid_trigger`, etc.) -
  not assumed from training-data recall. One real finding from doing
  this: `@bp.activity_trigger`/`@bp.orchestration_trigger` wrap a
  function in a `FunctionBuilder` with no supported way to call the
  original function back out of it - that's why `run_pre_flight_scan`
  and `*_generator` exist as separate, undecorated functions rather than
  the decorated ones being called directly anywhere in this codebase.
- **The full existing Culprit test suite stays green** (757 passed,
  including the 21 new tests above) - the `collection.py` refactor and
  this whole new package introduced no regression anywhere else.

## What has NOT been verified, and what real Azure access would confirm

This session had no Azure subscription, no Azure Functions Core Tools
(`func`), no Azurite emulator, and no Docker daemon available - so none
of the following has been run for real:

- **The Functions app has never actually run on a Functions host**
  (local `func start` or a real deployment). The orchestrator *logic* is
  tested; the Durable Functions *runtime machinery* around it (the
  Storage-backed Task Hub, replay semantics under real concurrency,
  activity retry/timeout behavior) is not.
- **The Docker image (`Dockerfile`) has never been built.** It's modeled
  tightly on the already-proven `culprit/Dockerfile` (same `PYTHONPATH`,
  same `COPY` layout, same vendored-`tcx_mailer` convention), but that
  similarity is not a substitute for an actual `docker build`. Smoke-test
  it on the lab host (10.60.76.195), which has Docker, before trusting it.
- **The Bicep template (`culprit/infra/main.bicep`) has never been run
  through `az bicep build` or `az deployment group what-if`** - no `az`
  CLI was available here. Validate both before applying it to a real
  resource group.
- **The native Event Grid trigger's subscription-validation handshake**
  is documented Azure Functions behavior (handled by the platform, not
  application code), but hasn't been confirmed against a real Event Grid
  topic from this session - and the underlying "what actually publishes
  a patch-run-completed event" question is exactly as unresolved as it
  was before this migration (see `event_grid_trigger`'s own docstring and
  the proposal doc's risk table - this port doesn't solve or worsen that).
- **The scheduled timer's cron expression is read from an app setting**
  (`%CULPRIT_SCHEDULE_CRON%`), not the DB - unlike today's Docker
  deployment, where editing the cron on `/culprit/settings` takes effect
  live. `scope_name`/`window_hours` ARE still read from the DB at fire
  time (same live-editable behavior as today). Changing the cron
  expression itself needs an app-setting update + a Function App restart,
  not a redeploy - a real, if small, behavior difference from today,
  flagged here rather than glossed over.

## Open decision needed before the frontend is touched

Removing GrowthBook (management's requirement) also removed its backend
container and `VITE_GROWTHBOOK_*` env vars - `portal/ui/src/lib/
growthbook.ts`'s `createGrowthBook()` now gets blank `apiHost`/
`clientKey`, which is GrowthBook's own standard no-op/disabled state:
every `useFeatureIsOn(...)` call across the Portal UI now resolves to its
default (off), with **zero frontend code changes** and zero risk of
breaking the build.

Four real feature checks are affected this way:
`portal.admin.bulk-user-import`, `portal.launcher.maintenance-banner`,
`shared.maintenance.readonly-mode`, `shared.beta.early-access` - all four
are now permanently off. If any of those should instead become
permanently *on* (not just silently off), or if you want the dead
`GrowthBookProvider`/`useFeatureIsOn` code physically removed from
`App.tsx`/`Admin.tsx`/`AppLauncher.tsx` rather than left as inert,
no-op code, that's a product decision this session didn't make for you -
say which of the four (if any) should flip to always-on, and whether to
clean up the dead code now or leave it as a documented no-op.

## Deploying for real (once the above is validated)

```bash
az bicep build --file culprit/infra/main.bicep
az deployment group what-if -g <resource-group> --template-file culprit/infra/main.bicep \
  --parameters namePrefix=culprit-<env> postgresAdminLogin=<...> postgresAdminPassword=<...>
az deployment group create -g <resource-group> --template-file culprit/infra/main.bicep \
  --parameters namePrefix=culprit-<env> postgresAdminLogin=<...> postgresAdminPassword=<...>

docker build -f culprit/culprit/serverless/Dockerfile -t culprit-serverless:latest .
# push to whatever registry the deployed Function App's linuxFxVersion points at,
# then update that image reference and restart the Function App.
```
