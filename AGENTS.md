# AGENTS.md — for coding agents working on this repository

This file is for Claude Code, Codex and people: how this repo is built,
tested and reviewed. It is **not** instructions for Culprit's own runtime
RCA agent — those live in `culprit/culprit/pipeline/rca_agent.py`'s system
prompt and are a different audience. Keep the two apart.

Ported and cut down from the platform's `test` branch, which carries the
same file for a six-app monorepo with its own `agents/` governance tree
(token budgets, immutable sections, eval-gated instruction changes). None
of that apparatus exists here — this repo is two apps, not a platform with
a prompt-instructions review process — so this file describes what's
actually here instead of referencing machinery that doesn't exist in it.

## What is here

Two apps, two separate databases by design: `portal/` (login, launcher,
admin - Postgres) and `culprit/` (autonomous root-cause analysis for
failed Azure Update Manager patch deployments - its own SQLite/Postgres,
kept off Portal's instance deliberately so the two can never collide; see
`docker-compose.yml`'s culprit-api comment). `shared/src/` is what both
import from: feature flags, and now `shared/src/llm/` (multi-provider AI
adapters) - see "Platform-wide AI providers" below. `docker-compose.yml`
runs the whole stack. `docs/SETUP.md` is the administrator setup guide;
`culprit/ARCHITECTURE.md`, `culprit/RUNBOOK.md` and `culprit/SECURITY.md`
are Culprit's own design, real-environment wiring, and security model
respectively - read those before changing culprit/, not this file.

### Platform-wide AI providers

Which LLM Culprit's deep RCA agent (and any future app that needs one)
calls is configured once, platform-wide, by an admin on the Portal's
Admin → AI Providers screen (`portal/api/routers/ai_providers.py`,
`portal/db.py::AIProviderSetting`) - not per-app, and not with a default:
until an admin picks one, `active_provider` is empty and every consumer
falls back to whatever it did before this screen existed (Culprit: its
own `ANTHROPIC_API_KEY` env var). The actual model call still happens
locally in whichever app needs it - Culprit's `api/deps.py::get_rca_agent`
fetches the resolved, decrypted config from Portal's internal
`GET /api/ai-providers/resolved-active` (a short-lived `type: "service"`
JWT it mints itself with the same secret Portal SSO already shares, not a
user session - see `portal/dependencies.py::require_service`) and builds
a client via `shared/src/llm/factory.py`, so the request goes straight
from Culprit to the provider instead of proxying through Portal. Adding a
provider means editing `shared/src/llm/catalog.py` once; every consumer
gets it for free.

## Run the tests

```bash
cd culprit && pytest -q          # 380+ tests, fully offline, no credentials needed
python -m pytest shared/tests -q  # shared/src/llm/'s adapter tests, also offline
cd portal/ui && npm install && npm run build   # tsc && vite build - the type-check is the half that catches things
```

Portal's Python side has no test suite yet (`portal/tests/` doesn't exist) -
its `AIProviderSetting`/`User` models use Postgres-only `JSONB` columns, so
a real test harness needs a real Postgres (or a JSON-column rewrite), not
just an in-memory SQLite swap. If you add one, wire it into whatever CI
config exists at the time, the same way `culprit/`'s is self-contained
under `culprit/tests/`. In the meantime, `portal/api/routers/ai_providers.py`
was verified by hand (importing the built app, then exercising the
service-vs-admin token boundary with `starlette.testclient.TestClient`)
rather than with a committed test file.

## Rules the existing code already enforces (so a change doesn't quietly break them)

- **No citation, no claim.** Every step in an `RCAResult.causal_chain`
  requires a non-empty `evidence_refs` list, enforced at the Pydantic model
  layer (`culprit/models/rca.py`) and cross-checked against the evidence
  bundle actually given to the model (`pipeline/rca_agent.py::_fabricated_refs`)
  - a well-formed but hallucinated reference is caught, not just an empty
    one. Extend this discipline to anything new that produces a claim from
    evidence; don't relax it to make a feature easier to ship.
- **Rules first, model for the tail.** `culprit/pipeline/rules.py`'s
  deterministic rulebook runs before the deep RCA agent and settles
  whatever it can without a model call - free, instant, auditable, cannot
  hallucinate. A new failure family the estate actually hits often enough
  to warrant automation belongs in `models/taxonomy.py` +
  `pipeline/rules.py` first; the model is for the genuinely ambiguous tail,
  not a shortcut around writing a rule.
- **Graceful degradation over a hard dependency.** Every optional
  integration (Azure, Datadog, the deep RCA model, agent memory) has a
  working fallback when its credential or package isn't present, or - for
  the deep RCA model specifically - when the Portal it now asks isn't
  reachable at all: see `api/deps.py::get_rca_agent` (Portal unreachable
  or nothing configured there -> legacy env var -> the scripted demo
  agent) and `get_retrieval_store` (falls back to the vendor-doc-only
  store when `culprit[memory]` isn't installed) for the pattern: try the
  real thing, catch the specific error, log once, return the fallback.
  Never let a missing optional extra - or another app being down - crash
  startup or a request.
- **Every write path names what may write to it.** Culprit's memory
  (`culprit/memory/`) accepts only a confirmed-correct `Verdict`; a
  "wrong" verdict never writes, it forgets. The precision gate
  (`models/taxonomy.py::PROMOTION_PRECISION_THRESHOLD`) only ever moves on
  real reviewed samples. If you add a new thing that writes durable state
  from a model's own output, decide and document what's allowed to trigger
  that write before you wire it up - "a model said so" is never enough on
  its own.
- **Self-hosted by construction, not by convention.** Where a design
  explicitly avoids sending data to a third party (Culprit's memory:
  on-disk Chroma + a local embedder), the code refuses a config that would
  route around that (`memory/store.py::assert_self_hosted`), it doesn't
  just default to the safe option and hope nobody changes it. Follow the
  same shape for anything else with the same property.
- **A reverse-proxy prefix is not optional to handle.** This app is always
  served both directly and under nginx's `/culprit/` (or `/portal/`)
  location prefix - see `culprit/api/root_path_middleware.py`'s docstring
  for the concrete bug this fixes. Any new redirect or internally-generated
  URL must go through the existing `root_path(request)` helper (or the
  template's `nav_prefix`, for a page several path segments deep), never a
  hardcoded absolute path.
- **A session's lifetime is sliding, not fixed, and only for the case that
  needs it.** `auth_middleware.py::_renew_session_cookie_if_portal_backed`
  re-signs Culprit's session cookie on every request so an actively-
  browsing user isn't logged out on a fixed wall-clock timer - but only
  for a Portal-JWT-backed **cookie**; the shared `CULPRIT_API_TOKEN` and a
  script's `Authorization: Bearer` header both re-send their own
  credential every call and are never "renewed". If you add another
  session-shaped credential, decide explicitly whether it slides or not -
  don't assume all auth state behaves the same way.
- **A persisted summary is not the audit trail it summarizes.**
  `MachineOutcomeRecord` persists each machine's `PatchOutcome` (status,
  error, failed KB/package) so the per-machine page can show it after a
  run finishes - it does not persist the raw `EvidenceBundle`/
  `TimelineEvent` list that summary was derived from, which is still a
  local variable that vanishes when `Pipeline.run()` returns (see
  `culprit/SECURITY.md`'s "Data retention and reproducibility", corrected
  2026-09-28 after this exact gap was found). If you add a new persisted
  summary, say plainly in its docstring what it does and doesn't let you
  reconstruct later - the previous version of that security doc claimed
  more than the code actually did.

## Where to look

| Question | Place |
|---|---|
| Culprit's overall design and what maps to which module | `culprit/ARCHITECTURE.md` |
| Wiring Culprit against a real Azure subscription / Datadog org | `culprit/RUNBOOK.md` |
| Culprit's security model, RBAC role, data handling | `culprit/SECURITY.md` |
| Culprit's agent memory (mem0) - what it stores, what it deliberately doesn't | `culprit/culprit/memory/__init__.py` |
| Portal's login/JWT/SSO design | `portal/README.md` |
| Platform-wide AI provider config - what's admin vs. service-to-service | `portal/api/routers/ai_providers.py` |
| The multi-provider AI adapters themselves (what's verified, what isn't) | `shared/src/llm/__init__.py` |
| Administrator setup after a first deploy | `docs/SETUP.md` |
| Original proposal this whole app implements | `culprit/README.md`'s own links, or ask for the proposal document directly - it isn't checked into this repo |

## How work lands

Commit messages say why, not only what - the existing history is the style
guide. Secrets and `.env` files are never read into a commit, a PR or a
log line. Before a destructive git operation (reset --hard, a force push,
discarding uncommitted work), check `git status` first - the usual rule,
not special to this repo.
