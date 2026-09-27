# Security

Phase 1 is read-only by construction: the credential Culprit runs as
cannot change a resource, not because it's told not to, but because it
has no permission to.

## Application authentication (`CULPRIT_API_TOKEN` + Portal SSO)

A review on 2026-09-27 found the app itself had **zero authentication
anywhere** - every route, including the `/settings` screen that can hold
real Azure/Datadog credentials and `POST /runs/live` (a real, costed
action against a real subscription), was open to anyone who could reach
the URL. Fixed in `culprit/api/auth_middleware.py`, with two independent
credentials either of which grants access:

1. **A shared token** (`CULPRIT_API_TOKEN`) - a **cookie**, set once by
   signing in at `/login`, for a human in a browser (the console/settings
   pages' own `fetch()` calls carry it automatically - nothing in their
   JS had to change); or an `Authorization: Bearer <token>` header for
   scripts/curl/CI.
2. **The AgentMesh Portal's own JWT** (`CULPRIT_PORTAL_JWT_SECRET`, the
   same signing secret as Portal's `SECRET_KEY` - see
   `security/portal_jwt.py`). Fixed the very next report after #1
   shipped: an already-authenticated platform user launching Culprit from
   the AgentMesh launcher was bounced to the same login wall as an
   anonymous visitor, because #1 had no idea Portal sessions existed.
   The launcher's one-time `?auth_token=<jwt>` handoff is now validated
   (signature, expiry, and that the user was actually granted Culprit
   access via Admin's per-user checkboxes - `"culprit" in app_access`)
   and converted into the same session cookie as #1, so it survives past
   that first request.

**If neither env var is ever set, authentication is disabled entirely**
(fail *open*) - this is what keeps the demo and the test suite working
with zero configuration, and it's loudly logged at startup so it can't be
missed silently (see `main.py`'s lifespan handler). Generate a real
`CULPRIT_API_TOKEN` before this ever holds real credentials:
`python -c "import secrets; print(secrets.token_urlsafe(32))"`.
`/health`, `/login`, and `/webhooks/event-grid` are always public - the
first two by necessity, the third because Event Grid's own handshake
can't carry either credential.

## RBAC

`culprit/security/rbac/culprit-reader-role.json` is the complete custom
Azure role Culprit needs. Notable points:

- `Actions` is entirely `*/read` - Resource Graph, Activity Log, Log
  Analytics query, Maintenance configuration read, policy/lock read. There
  is no `*/write`, no `Microsoft.Compute/virtualMachines/write`, no
  Contributor-equivalent action anywhere in the role.
- The one `DataActions` entry,
  `Microsoft.Compute/virtualMachines/runCommands/action`, is what actually
  invokes Run Command against a guest OS. This is the one place the role
  alone isn't the whole story - RBAC would technically allow running any
  script via Run Command, which is why the application layer constrains
  it further: `collectors/guest_linux.py` and `collectors/guest_windows.py`
  hard-code a fixed, reviewed, read-only script (`ALLOWED_LINUX_SCRIPT`,
  `ALLOWED_WINDOWS_SCRIPT`). There is no code path anywhere in this
  repository that accepts an arbitrary script or interpolates
  caller-supplied text into a Run Command invocation. Extending what the
  guest collectors can read requires a code change and a review, not a
  config change.
- Assign this role, and only this role, to the identity Culprit runs as
  (a managed identity in production - `DefaultAzureCredential` picks it up
  with no code change). Do not additionally grant Contributor "just in
  case."

## Datadog and the RCA model

- Every Datadog API call in `collectors/datadog_collector.py` is a `list`
  / `query` call (`query_metrics`, `list_monitors`, `list_logs`) - no
  mutating Datadog endpoint is called anywhere.
- The RCA agent (`pipeline/rca_agent.py`) has no tools of its own beyond
  `submit_rca_finding` - it cannot call back into Azure, Datadog, or
  anything else. It only ever sees the evidence bundle text it's handed;
  it has no path to take any action.

## Scrubbing before reasoning

`security/scrub.py` strips credential-shaped content (AWS keys, bearer
tokens, basic-auth URLs, generic `password=`/`secret=`/`token=` patterns,
PEM private key blocks) from every `TimelineEvent` before it can reach a
prompt. This runs on **collector output**, not on the model's output - the
point is a secret never enters the prompt in the first place. IP
addresses and email addresses are left alone by default (often legitimate
evidence - the host in a log line) but can be redacted too via
`CULPRIT_SCRUB_PII=true` for a stricter compliance posture.

Apply `scrub_events()` to a bundle's timeline before it's handed to
`rca_agent.diagnose()` in any deployment that collects from an estate
where this matters - it isn't wired into the orchestrator unconditionally
because whether IP/email redaction is desired is an environment-specific
policy decision, made via `config.py::settings.scrub_network_and_pii`.

## Connection settings (the `/settings` screen)

The Azure client secret and Datadog API/app keys entered on `/settings`
are encrypted at rest (Fernet, `culprit/security/crypto.py`), keyed by
`CULPRIT_ENCRYPTION_KEY` - set this in any real deployment; an insecure,
clearly-marked dev-only default keeps the screen usable with zero
configuration otherwise. Every `GET` of a settings view
(`culprit/db/repository.py::azure_settings_view` /
`datadog_settings_view`) reports only whether a secret is configured,
never the value - the ciphertext is decrypted only in-memory, at the
point of an actual Azure/Datadog call (`load_azure_settings` /
`load_datadog_settings`), and is never logged or returned over the API.
Updating settings with a blank secret field leaves the previously-saved
secret untouched rather than wiping it - see the "leave alone if blank"
handling in `save_azure_settings`/`save_datadog_settings`.

`CULPRIT_ENCRYPTION_KEY` not being set is loudly warned about at startup
(see the app-authentication section above) - previously it degraded
silently. If the key is ever rotated after secrets were saved under a
different one, `POST /runs/live` now fails with a clear "re-enter your
settings" message (`cryptography.fernet.InvalidToken`, caught explicitly
in `api/routes_runs.py`) instead of an unhandled 500.

The settings page's own status display was a **stored-XSS vector** until
2026-09-27: a provider error message (`last_test_message`, echoed back
verbatim from Azure/Datadog) was concatenated into an `innerHTML`
assignment. Fixed by building that element with `textContent`/
`createTextNode` exclusively (`reporting/templates/settings.html.j2`),
which never parses its input as HTML regardless of content.

## Query construction

Every Resource Graph/Log Analytics query the collectors and
`pipeline/discovery.py` build interpolates a VM id, computer name, or
resource id into a KQL/OData string literal via `.format()`. These values
come from Azure's own resource metadata, not directly from an untrusted
caller, so exploitability was assessed as low - but there was no
escaping at all. `security/kql.py::escape_kql_string()` (KQL/OData's
single-quote-doubling rule) is now applied everywhere a value is
interpolated into a string literal, as defense in depth against a
resource name or tag that happens to contain a `'`.

## Citation accuracy vs. citation presence

The Pydantic validation on `CausalStep.evidence_refs`
(`models/rca.py`) only ever checked that citations were present and
non-blank - it never checked that a cited `raw_ref` actually exists in
the `EvidenceBundle` the model was given, so a well-formed but
hallucinated reference passed cleanly. `pipeline/rca_agent.py` now cross-
checks every `evidence_refs` entry against the bundle's real `raw_ref`
set after parsing the model's tool call, and downgrades to the same
low-confidence "unresolved" result the other validation failures use if
any citation doesn't resolve to real evidence.

## A crash mid-run no longer leaves the run stuck

`RunStage.FAILED` existed in the schema but nothing ever set it - a
crash partway through diagnosis (a Claude API error, a DB error, an
exception from a real Azure call inside the `missing_evidence`
re-collection path) left the run permanently at `CLUSTERED`, with no way
to distinguish "still running" from "died an hour ago." `pipeline/orchestrator.py::Pipeline.run`
now marks the run `FAILED` (via a fresh DB session, since the one the
error occurred in may be mid a broken transaction) before re-raising, so
the original error still propagates to the caller.

## Data retention and reproducibility

Every evidence bundle collected is retained (as `TimelineEvent`s
persisted alongside the `RCAResult` in `db/models.py`), addressable by
`raw_ref`, so any RCA can be re-derived and audited months later. Every
guest Run Command invocation and every Resource Graph/Activity
Log/Datadog read happens under the identity's own audit trail in that
service - Culprit does not add a separate audit log for reads that Azure
and Datadog already log natively.

## Reporting a concern

This is a Phase 1, read-only analysis tool with no write path to
production infrastructure. If you find a way for it to change a resource,
exfiltrate a secret past `scrub.py`, or have the RCA agent take an action
beyond returning its structured finding, that's a bug against the
guarantees stated above - treat it as a priority fix, not a Phase 2
concern.
