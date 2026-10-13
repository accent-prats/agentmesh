# Architecture

This maps the pipeline design onto the actual code, in the order data
flows through it. Read this alongside `README.md`'s "what's real"
section if you're deciding what to trust without a live environment to
test against.

## The pipeline

```
Trigger -> Collect -> Normalize -> Fingerprint/Cluster -> Rule engine
                                                              |
                                                   settled?  yes -> done
                                                              |
                                                              no
                                                              v
                                                   Deep RCA (claude-opus-5)
                                                              |
                                                     missing_evidence? -> recollect -> re-diagnose (once)
                                                              |
                                                          Advisor
                                                              |
                                                    Persist + Fleet report
                                                              |
                                                  Teams/Slack/API/chat
```

### 1. Trigger (`culprit/scheduler/`)

Four modes, all converging on the same `Pipeline.run()`:

- **Scheduled** (`scheduler/cron.py::scheduled_cycle`) - cron aligned to a
  maintenance window, offset to fire after it closes.
- **Event-driven** (`scheduler/events.py`) - a webhook receiver that
  correctly handles Event Grid's subscription-validation handshake. The
  honest caveat: Azure Update Manager doesn't publish a documented,
  stable Event Grid system topic for "run completed" as of this writing,
  so the actual event source (an Activity Log alert's Action Group
  webhook, or a small poller) is a Phase 1c wiring decision left explicit
  in that file rather than invented.
- **Ad-hoc** (`api/routes_runs.py::trigger_demo_run`, `api/routes_chat.py`)
  - the demo route and the chat endpoint.
- **Pre-flight** (`scheduler/cron.py::pre_flight_check`) - runs the rule
  engine (no model, no cost) against *current* state between cycles, to
  predict failures before the next window opens.

### 2. Collect (`culprit/collectors/`, `culprit/pipeline/collection.py`)

Four collectors, one per evidence plane, all implementing the same
`Collector` protocol (`collectors/base.py`) so the orchestrator never
distinguishes real from fixture:

- `azure_control_plane.py` - Resource Graph (`patchinstallationresources`)
  + Activity Log.
- `azure_monitor.py` - Log Analytics: Heartbeat gaps, Windows `Event` /
  Linux `Syslog` around the window.
- `guest_linux.py` / `guest_windows.py` - Run Command with a **fixed,
  reviewed, read-only script** (never arbitrary execution), plus real
  regex parsers for dpkg/apt/yum/CBS/WindowsUpdate log formats. The
  parsers are pure functions, unit-tested directly against real log text
  in `tests/test_guest_linux_parsers.py` / `test_guest_windows_parsers.py`
  without needing a live VM.
- `datadog_collector.py` - metrics (disk/memory trend into the window),
  monitor state, logs/events (the post-reboot regression signal).

`pipeline/collection.py::collect_all` fans these out in parallel per
machine; `collect_all` -> `normalize.merge_bundle` -> one `EvidenceBundle`
per machine, with a per-source `error` becoming a `collection_gaps` note
rather than silently vanishing.

### 3. Normalize (`culprit/pipeline/normalize.py`)

Merges each machine's `CollectionResult`s into one chronological
`EvidenceBundle` (`models/evidence.py`). Every fact carries a `raw_ref`
pointer back to its source - this is what makes "no citation, no claim"
enforceable in step 5.

### 4. Fingerprint & cluster (`culprit/pipeline/fingerprint.py`)

The load-bearing design decision. A deterministic fingerprint (normalized
error code, OS family, failing target with version numbers stripped,
extension state, a sorted precondition signature) collapses hundreds of
failures into a handful of clusters *before* any model runs. No model is
involved anywhere in this file - reproducible, free, and immune to a
model's mood. `fingerprint_id()` is stable across runs, which is what lets
`advisor.py` detect a repeat offender.

Tested in `tests/test_fingerprint.py`: identical failures collapse,
different failures separate, successes are excluded, the id is stable
across superficially different machines.

### 5. Rule engine (`culprit/pipeline/rules.py`)

Eight deterministic rules, each a plain predicate: disk exhaustion, agent
not ready, reboot starvation, orchestration mismatch, package-manager
lock, machine unavailable, source/entitlement, permission/policy. Every
rule requires corroborating evidence before firing (e.g. disk-low *and* an
actual write failure, not just a low-disk metric) - the over-firing guard
is tested explicitly in `test_rules.py`. Window exhaustion has **no rule**
by design - the proposal treats it as always a symptom that must escalate.
Whatever no rule settles returns `None` and falls through to step 6.

### 6. Deep RCA (`culprit/pipeline/rca_agent.py`)

`claude-opus-5` by default, structured output via a **strict** tool
definition (`submit_rca_finding`, `additionalProperties: false`,
`required` fields) - requested through the schema, not just the prompt.
Every `evidence_refs` entry is enforced non-empty at two layers: the tool
schema's `minItems: 1` *and* a Pydantic validator on `CausalStep`
(`models/rca.py`) - belt and suspenders, since a strict tool schema
constrains structure but not content. A model-level validator on
`RCAResult` additionally blocks a "confident nothing": `confidence >= 0.5`
with an empty `causal_chain` is rejected outright. This enforcement is
provider-agnostic by construction - it runs in `rca_agent.py` itself,
after whatever client answered, not inside any one provider's SDK.

`DeepRCAAgent` is deliberately written against a narrow
`AnthropicClientLike` protocol (`client.messages.create(...) -> response`
with `.content`/`.stop_reason`), not the Anthropic SDK directly, which is
what lets a different provider stand in without this file changing at
all: `api/deps.py::get_rca_agent()` fetches which provider is active from
the AgentMesh Portal's platform-wide, admin-managed AI Providers screen
(`portal/api/routers/ai_providers.py` - a service-to-service call, not a
local DB read, since that config is shared across every app on the
platform, not owned by Culprit) and builds the matching client via
`shared/src/llm/factory.py`. No provider configured there, or Portal
unreachable (e.g. Culprit running standalone) -> falls back to the
original `ANTHROPIC_API_KEY` env var, then to the scripted demo agent.
See `shared/src/llm/__init__.py` for the adapter catalog and what's
actually been verified against each provider.

If the agent's output fails validation for any reason, or it doesn't call
the tool at all, `rca_agent.py` degrades to a low-confidence "unresolved"
result rather than propagating a malformed answer - tested in
`tests/test_rca_agent.py` against a fake Anthropic client and in
`tests/test_llm_adapters_e2e.py` against a fake OpenAI-compatible one,
both exercising exactly the interface a real client returns (`tool_use`
blocks with `.name`/`.input`), so these paths are verified without a
network call.

`missing_evidence` in the result triggers one targeted re-collection pass
(`orchestrator.py`'s `recollect_fn` hook -> `collection.py::recollect_targeted`)
before falling back to whatever confidence the agent could reach - "two
targeted passes beat one speculative one."

### 7. Advisor (`culprit/pipeline/advisor.py`)

Two things that have to happen regardless of which path (rule or model)
produced the result: (1) a structural safety net - a high-risk immediate
fix is never left marked as a Phase 2 automation candidate, overridden
here even if the model or a rule author got it wrong; (2) recurrence
detection - `fingerprint_id` (stable across runs) plus the run history in
`db/repository.py::historical_cluster_keys` gives the "Nth cycle
recurring" badge from consecutive-run presence, not lifetime count.

### 8. Persist & report (`culprit/db/`, `culprit/reporting/`)

Every stage checkpoints to SQL (`RunStage` in `db/models.py`) so a crash
mid-cycle resumes rather than re-collecting from scratch. `reporting/fleet_report.py`
builds the ranked, three-altitude report the proposal describes (fleet /
cause / machine); `reporting/render.py` renders it to HTML;
`reporting/notify.py` posts a real Teams MessageCard or Slack Block Kit
payload to a webhook URL.

The third altitude's own data - each machine's `PatchOutcome` (status,
error code/message, the specific failed KB(s)/package(s)) and collection
gaps - is persisted per run in `MachineOutcomeRecord` (`db/models.py`),
written once per cluster right alongside its RCAResult
(`repository.save_machine_outcomes`, called from `orchestrator.py::Pipeline.run`)
and read back by `GET /runs/{run_id}/machines/{vm_name}.html`. Added
after the rest of this schema - the `EvidenceBundle` it's drawn from was
previously a local variable that vanished once a run finished, so a
machine's own outcome could only ever be shown while its request was
still in flight, never afterward; runs diagnosed before this table
existed simply have none, and the machine page says so rather than
showing stale or fabricated detail. `GET /runs.html` lists every run
ever diagnosed (`repository.list_runs`) - "which update jobs is Culprit
monitoring," the report's zeroth altitude.

## The Phase 2 gate

`models/verdict.py::compute_family_precision` tracks precision **per
`CauseFamily`**, not as one aggregate number. `FamilyPrecision.meets_promotion_bar()`
is the entire gate: `sample_size >= 50 and precision >= 0.95` (both
configurable via `CULPRIT_PROMOTION_MIN_SAMPLE` / `CULPRIT_PROMOTION_THRESHOLD`).
`GET /precision` is the one view that decision gets made from. Nothing in
this repository promotes a family to fully autonomous action - the gate
produces a number and a boolean, re-read live on every single execution
attempt, never cached or trusted from an earlier check. A human decision
is required for every individual remediation, even for a cause family
that has cleared the gate - see "Remediation execution" below.

## Remediation execution

The one place `meets_promotion_bar()` and a diagnosis's own
`phase2_candidate` flag (set per-diagnosis by the rule engine/RCA agent,
asserting "this kind of fix is mechanical/bounded/reversible" -
independent of precision data) are AND'd together and actually acted on:
`api/routes_remediation.py::execute_remediation`. Both conditions are
re-checked fresh on every request, alongside a feature flag
(`CULPRIT_REMEDIATION_ENABLED`, off by default) and a required
caller-supplied `requested_by` - there is no code path that skips any of
these, and no fully-autonomous/zero-touch variant exists anywhere.

`culprit/remediation/` holds the one wired action (disk cleanup,
`CauseFamily.CAPACITY`) - `scripts.py`'s allow-listed Linux/Windows
scripts, executed via `runner.py`'s `RemediationRunner` (mirrors
`collectors/guest_linux.py`'s exact Run Command invocation pattern). Every
attempt, success or failure, is persisted to `RemediationActionRecord`
(`db/models.py`) - an append-only audit log, not an upsert, since the same
machine can legitimately be remediated more than once over time - readable
at `GET /remediation/log.html`.

See `SECURITY.md`'s "Remediation execution" section for the full
guarantee this is held to.

## Design deviations from a literal reading of the proposal, and why

- **Phase 2 scoped to exactly one cause family's one action, not a
  generic automation framework.** `phase2_candidate=True` is necessary but
  not sufficient to execute - a wired `action_type` in
  `models/remediation.py::SUPPORTED_ACTIONS` is also required, so every
  other `phase2_candidate` family still surfaces a human playbook only
  until it gets its own reviewed `RemediationRunner` method and allow-listed
  script.

- **No separate "Advisor" LLM call.** Both the rule engine and the RCA
  agent produce a `RemediationPlaybook` directly as part of their own
  output, since a second call would just re-read the same context for no
  real gain. `advisor.py` still exists as its own module - it does the two
  things that genuinely need to happen *after* either path, not a second
  model round-trip.
- **SQLite by default, not Postgres.** Nothing in the proposal requires
  Postgres specifically; `db/engine.py` reads `CULPRIT_DATABASE_URL` and
  the schema (`db/models.py`) is plain SQLAlchemy, so pointing it at
  Postgres for production is a one-line config change, not a rewrite.
- **A dependency-light retrieval store for vendor docs, a real vector
  store for confirmed RCAs.** `retrieval/store.py` stays TF-IDF-style
  retrieval for the small, fixed vendor-doc seed set - no external service
  needed for the demo or the test suite. Confirmed RCAs are the part that
  actually grows and benefits from real embeddings as the corpus grows
  over months (the proposal's own "sharper in month six" framing) - that's
  what `memory/` (mem0, on-disk Chroma) is for, optionally, behind
  `CULPRIT_MEMORY_ENABLED`. `retrieval/hybrid.py` combines both behind the
  same interface (`.render_context()`, `.add_resolved_incident()`) the
  plain store already exposed, so nothing above either one needed to
  change.
- **No React dashboard.** Out of scope for this pass - see README.
