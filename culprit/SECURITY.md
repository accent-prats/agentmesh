# Security

Culprit's diagnosis path is read-only by construction: the credential it
runs as has no RBAC write permission to any ARM resource, and nothing in
collection or deep RCA can invoke anything but a read - not because it's
told not to, but because it has no permission to. The one deliberate
exception is remediation execution (see "Remediation execution" below) -
a small, explicitly reviewed, hardcoded allow-listed action, gated on a
precision threshold re-verified live and a required human confirmation
per action, off by default.

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

### Sliding-session renewal (2026-09-27)

The Portal-SSO cookie set by #2 above, and the JWT payload inside it,
both originally hard-expired 60 minutes after the *moment Portal issued
the token* - not renewed by activity. An actively-browsing user got
logged out on that fixed wall-clock timer mid-session, bounced to the
`CULPRIT_API_TOKEN` login screen - an operator secret an ordinary
AgentMesh user has no way to know, with no working recovery path from
there.

`RequireApiTokenMiddleware` (`auth_middleware.py`) now re-signs and
re-sets the cookie (`security/portal_jwt.py::renew_portal_token` - same
claims, a fresh 60-minute `exp`) on every request authenticated via a
Portal-JWT **cookie**, so the window is "60 minutes since your last
click," not "60 minutes since you logged in." Deliberately scoped to
that one case only:

- The shared `CULPRIT_API_TOKEN` (cookie or Bearer) is never renewed -
  it has no expiry to renew; it authenticates the same way every time
  it's presented.
- A script's `Authorization: Bearer <portal JWT>` header is never
  renewed either - a script re-sends its own credential on every call
  and has no cookie jar to benefit from a `Set-Cookie` response, so
  none is sent for that path.

This does not change the *authorization* check at all (still `"culprit"
in app_access`, or `admin`/`ci_service`) - only how long a validated
session keeps working without the user re-authenticating with Portal.
An admin revoking a user's Culprit access mid-session still takes effect
on their *next* Portal-issued token, the same as before; this renewal
re-signs the claims already present in the cookie, it doesn't re-check
them against the Portal's `users` table (Culprit has none of its own -
see `security/portal_jwt.py`'s docstring).

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

The Azure client secret and Datadog API/app keys (or a Datadog Personal
Access Token - added 2026-10-11, an alternative to the API/app key pair,
see `collectors/datadog_auth.py`) entered on `/settings` are encrypted at
rest (Fernet, `culprit/security/crypto.py`), keyed by
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
handling in `save_azure_settings`/`save_datadog_settings`. The Datadog
API/app key pair and a Personal Access Token are mutually exclusive, not
three independent secrets: switching the settings screen's toggle from
one to the other explicitly forgets the one no longer in use, rather than
leaving it as an orphaned, unused ciphertext.

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

## AI provider credentials (platform-wide, owned by Portal)

Unlike Azure/Datadog above, the deep RCA agent's own AI provider
credentials are **not** Culprit's to encrypt or store - they're a
platform-wide setting an admin configures once on the Portal (Admin →
AI Providers), shared by every app that needs an LLM call. This is a
deliberately different trust shape from everything else in this file,
so it's worth spelling out precisely:

- Encrypted at rest with the Portal's own key (`PORTAL_ENCRYPTION_KEY`,
  Fernet, `portal/crypto.py`) - a separate key from Culprit's own
  `CULPRIT_ENCRYPTION_KEY`, so neither app's secrets are decryptable
  with the other's key.
- The admin-facing views (`GET /api/ai-providers`) never return a
  decrypted key, only whether one is configured - the same "configured:
  bool, never the value" rule Culprit's own `/settings` screen follows.
- Exactly one endpoint ever returns a decrypted key:
  `GET /api/ai-providers/resolved-active`, gated by
  `portal/dependencies.py::require_service` - a short-lived (5 minute)
  `type: "service"` JWT that the *calling app* mints itself with the
  same shared secret Portal SSO already trusts
  (`CULPRIT_PORTAL_JWT_SECRET` on Culprit's side), not a real user
  session. A leaked service token is a narrow, time-boxed exposure (the
  currently-active provider's credential, for up to 5 minutes), not a
  standing credential.
- That service token is deliberately a different `type` claim than a
  real user's Portal access token, checked explicitly
  (`payload.get("type") != "service"`), so a stolen or logged user
  session token can never be replayed against this endpoint, and a
  service token can never be used to sign into the admin UI - each
  side's `require_admin`/`require_service` dependency only accepts its
  own claim shape.
- The actual model call happens directly from the consuming app (e.g.
  Culprit) to the provider - Portal is never in that request path and
  never sees the prompt or the response, only the credential lookup at
  the start of a run.

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

**Corrected 2026-09-28 - this section previously overstated what's kept.**
The cluster (fingerprint + membership) and the `RCAResult` (cause,
confidence, causal chain, remediation) are persisted in `db/models.py`
and never expire on their own - that part was accurate. The raw
`EvidenceBundle` each diagnosis actually reasoned over - the full
`TimelineEvent` list, addressable by `raw_ref` - was **not**: it's a
local variable inside `pipeline/orchestrator.py::Pipeline.run()` that's
garbage-collected the moment a run finishes. Nothing in this repository
re-derives or audits the original raw evidence for a past run; only the
finding it produced.

`MachineOutcomeRecord` (`db/models.py`, added 2026-09-27) narrows that
gap for the one summary a reviewer actually asks for first - each
machine's own `PatchOutcome` (status, error code/message, the specific
failed KB(s)/package(s), reboot status, the run window) is now
persisted per run and shown on `/runs/{run_id}/machines/{vm_name}.html`.
It is a **summary**, not the audit trail: the underlying timeline
(individual Resource Graph rows, guest log lines, Datadog points) that
produced that summary is still not retained anywhere Culprit controls.
If your compliance posture requires reproducing the *exact* evidence an
RCA was based on months later, that currently has to come from Azure's
and Datadog's own logs (see the audit-trail note below), not from
Culprit's own database.

Every guest Run Command invocation and every Resource Graph/Activity
Log/Datadog read happens under the identity's own audit trail in that
service - Culprit does not add a separate audit log for reads that Azure
and Datadog already log natively.

## Remediation execution

The one deliberate exception to "read-only by construction": a single
hardcoded, allow-listed disk-cleanup action (`culprit/remediation/`,
`POST /remediation/runs/{run_id}/clusters/{cluster_id}/execute`). It can
only run when **all** of the following hold at the moment of the request,
re-verified live every time, never cached or trusted from an earlier
check:

- `CULPRIT_REMEDIATION_ENABLED=true` is explicitly set - **off by
  default**.
- The specific diagnosis is marked `phase2_candidate=True`.
- The diagnosed cause family currently clears the precision gate
  (`>=95%` precision over `>=50` reviewed instances, same bar `/precision`
  shows).
- A human supplies their own identity (`requested_by`) and explicitly
  confirms the action for that specific cluster.

There is no fully-autonomous or zero-touch path, ever, even for a cause
family that has cleared every other condition. The RBAC role this reuses
(`culprit-reader-role.json`) already grants the Run Command `DataAction`
needed - no new Azure permission was added for this; the only boundary is
the fixed script content reviewed into `culprit/remediation/scripts.py`,
held to the same "extending this needs a code review, not a config
change" bar the read-only collectors' own allow-lists already use.

## Reporting a concern

Culprit's analysis/diagnosis path remains read-only with no write path to
production infrastructure - the RCA agent still has no tool beyond
`submit_rca_finding`. Remediation execution (above) is the one narrow,
deliberate exception, bounded by every condition listed there. If you
find a way for it to change a resource outside remediation execution,
exfiltrate a secret past `scrub.py`, have the RCA agent take an action
beyond returning its structured finding, or execute a remediation action
missing any one of the conditions above (flag off, not phase2_candidate,
gate not met, or no human confirmation), that's a bug against the
guarantees stated above - treat it as a priority fix.
