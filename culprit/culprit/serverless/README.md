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
  just written and trusted: `tests/test_serverless_orchestrators.py` (7
  tests) drives both orchestrators as plain Python generators
  (Microsoft's own documented pattern for testing Durable Functions
  orchestrators - no live Functions host or Azure Storage emulator
  needed, since an orchestrator is deterministic code that only ever
  yields activity calls). Two tests specifically guard against real
  regression classes, both sabotage-proven (temporarily broke the fix,
  confirmed the test fails, restored it, confirmed green again):
  1. A cluster's recollected representative bundle must reach both the
     second deep-RCA call *and* persistence, not just the RCA call while
     the stale pre-recollection bundle silently gets persisted (the
     exact bug `pipeline/orchestrator.py::Pipeline.run`'s own docstring
     documents fixing for the Docker deployment on 2026-10-19).
  2. `near_misses`/`retrieval_context` must be computed once (via
     `compute_rca_context_activity`) and reused verbatim for the post-
     recollection re-diagnosis call, not recomputed against the
     recollected bundle - found in review 2026-11-10 as a real fidelity
     gap from `Pipeline._diagnose_one`'s own behavior (it computes both
     once and reuses them for the re-diagnosis call too).
- **Serialization is verified against real model instances**
  (`tests/test_serverless_serialization.py`, 5 tests), not just "the
  function exists" - round-tripping a real `EvidenceBundle`/`Cluster`/
  `RCAResult`/`PatchRun` through `.model_dump(mode="json")` and back.
- **The whole module tree imports cleanly** against the real `culprit`
  package (`python -c "import culprit.serverless.function_app"`),
  registering all 16 functions (4 triggers + 2 orchestrators + 10
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
- **The full existing Culprit test suite stays green**: 755 passed (743
  baseline + 12 new tests in this package) - no regression anywhere else
  from the `collection.py` refactor or this new package. Re-verify this
  number yourself before trusting it for long - it drifts as the suite
  grows, and an earlier version of this README overclaimed it (said 757/21
  when the real numbers were lower) - a mistake an independent review
  caught by actually re-running the tests, not by reading the claim.
- **An independent review (2026-11-10) found and this package then
  fixed**: the `near_misses`/`retrieval_context` fidelity gap above, plus
  two real Bicep deployment-blockers (a Consumption-plan + custom-
  container mismatch, and a missing `keyVaultReferenceIdentity` that
  would have silently broken Key Vault secret resolution) - see
  `culprit/infra/main.bicep`'s own comments at both fixed spots. Also
  removed an unused, dead `CollectionResult` (de)serializer pair from
  `serialization.py` that review correctly flagged as having zero real
  callers.

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
  resource group. This caveat is not theoretical: an independent review
  (2026-11-10), working by static read-through alone, found two real bugs
  a `what-if` run would very likely have caught on the first try - a
  Consumption-plan hosting plan paired with a custom-container Function
  App (not a supported combination; fixed to Elastic Premium) and a
  missing `keyVaultReferenceIdentity` that would have silently broken
  both Key Vault secret references at runtime. Both are fixed now, but
  the lesson stands: static review catches what it catches, and this
  template still needs a real `what-if` before anyone trusts it fully.
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

The template now provisions its own Azure Container Registry (found while
preparing the implementation/deployment proposal, 2026-11-10 - an earlier
version left the registry as an unresolved placeholder) - so the first
deployment creates an empty registry before any image exists to push.
Deploy, THEN build/push, THEN the Function App's first successful start
happens:

```bash
az bicep build --file culprit/infra/main.bicep
az deployment group what-if -g <resource-group> --template-file culprit/infra/main.bicep \
  --parameters namePrefix=culprit-<env> postgresAdminLogin=<...> postgresAdminPassword=<...>
az deployment group create -g <resource-group> --template-file culprit/infra/main.bicep \
  --parameters namePrefix=culprit-<env> postgresAdminLogin=<...> postgresAdminPassword=<...>

# The registry now exists but is empty - build and push before the
# Function App can start successfully:
REGISTRY=$(az deployment group show -g <resource-group> -n main --query properties.outputs.containerRegistryLoginServer.value -o tsv)
az acr login --name "$REGISTRY"
docker build -f culprit/culprit/serverless/Dockerfile -t "$REGISTRY/culprit-serverless:latest" .
docker push "$REGISTRY/culprit-serverless:latest"
# The Function App should now pull successfully on its own; if it was
# already running, restart it once to force an immediate pull.
```
