# AgentMesh — Administrator Setup Guide

This guide covers everything an admin needs to configure the platform after first deployment.

**Contents:**
1. [First Login](#1-first-login)
2. [User Management](#2-user-management)
3. [AI Providers (platform-wide)](#3-ai-providers-platform-wide)
4. [Culprit — Azure & Datadog Connections](#4-culprit--azure--datadog-connections)
5. [Feature Flags (GrowthBook)](#5-feature-flags-growthbook)
6. [Verification](#6-verification)

---

## 1. First Login

The Portal creates its own database schema and seeds a first admin account automatically
the first time it starts (`portal/db.py::bootstrap`) — there's no separate migration step.

| Variable | Default | Description |
|---|---|---|
| `PORTAL_ADMIN_EMAIL` | `admin@example.com` | Seeded admin's email |
| `PORTAL_ADMIN_PASSWORD` | `ChangeMe123!` | Seeded admin's password |

Set both in `.env` **before** the first `docker compose up`, or log in with the defaults and
change the password immediately from the app launcher's **Change password** button.

---

## 2. User Management

**Admin → User Management** lets you:
- Create new users (email, name, password, role, app access)
- Toggle a user's role (`admin`, `user`, `read_only`, `ci_service`)
- Grant/revoke Culprit access via the per-user checkbox
- Activate/deactivate an account
- Reset any user's password without knowing their current one

Admins and `ci_service` accounts always see every registered app regardless of their own
`app_access` list — see `portal/api/routers/apps.py::list_accessible_apps`.

---

## 3. AI Providers (platform-wide)

**Admin → AI Providers** configures which LLM the deep RCA agent uses — Culprit today, any
future app that needs one tomorrow. This is deliberately **not** a per-app setting: it lives in
the Portal's own database (`portal/db.py::AIProviderSetting`), not Culprit's, and every catalog
provider (Anthropic, OpenAI, Azure OpenAI, Gemini, Grok, Qwen, DeepSeek, Ollama, LM Studio) can
be configured and tested here regardless of which app ends up using it.

There is **no default provider**. Until an admin picks one and marks it active, every consuming
app falls back to whatever it did before this screen existed — for Culprit, that's the
`ANTHROPIC_API_KEY` environment variable (see §4 below), then a scripted stand-in if even that
is unset. Flipping the active provider here takes effect on the *next* request each app makes —
no redeploy, no restart.

For each provider: fill in the endpoint (most have a sensible default; Azure OpenAI needs your
resource's actual endpoint), pick a model from the dropdown (or choose **Other (custom)** to type
one not in the list — a renamed or newly-released model id never blocks saving), and an API key,
then **Save**. **Test connection** makes a real, minimal call (a model-catalog fetch for
Anthropic/Gemini, a one-token completion for the rest) before you commit to it. Secrets are
encrypted at rest (`PORTAL_ENCRYPTION_KEY`) and never echoed back by any GET.

**Clear active provider** (next to the provider list) returns to "nothing configured" — every
consuming app falls back to its own pre-existing behavior again, the same as if no admin had ever
touched this screen.

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Set the result as `PORTAL_ENCRYPTION_KEY` before saving any real provider API key.

---

## 4. Culprit — Azure & Datadog Connections

Culprit's own **Settings** screen (`/culprit/settings`, linked from its console) is where you
configure the credentials it needs to collect evidence:

- **Azure**: tenant ID, client ID/secret (or leave blank to use a managed identity via
  `DefaultAzureCredential`), and the subscription(s) to scan. Assign the identity
  `culprit/security/rbac/culprit-reader-role.json` — a read-only custom role — and nothing more.
- **Datadog**: API key + application key, used only for read-only `list`/`query` calls.

Every `GET` of the settings screen reports only whether a secret is configured, never the
value — secrets are encrypted at rest (Fernet) and decrypted only in-memory at the point of
an actual Azure/Datadog call. See [culprit/SECURITY.md](../culprit/SECURITY.md) for the full
security model.

Set `CULPRIT_ENCRYPTION_KEY` before saving any real credentials:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Portal single sign-on

An already-authenticated Portal user who clicks the Culprit card is signed in automatically —
no separate Culprit login. This requires `CULPRIT_PORTAL_JWT_SECRET` (Culprit) to match
`SECRET_KEY` (Portal). See [portal/README.md](../portal/README.md#configuration).

### Demo scenario (disable for a real deployment)

Culprit's console page (`/culprit/`) has a "Demo scenario" card that runs the full pipeline
against a synthetic 312-machine fleet — no Azure/Datadog credentials needed, useful for a
rehearsal or kicking the tires. It's on by default. Before a deployment any real stakeholder
or end user reaches directly, set `CULPRIT_DEMO_ENABLED=false` — this hides the card *and*
404s the underlying `POST /runs/demo` route itself, so a live system never exposes a button
that fabricates fake data.

### Autonomous scheduling (optional)

By default Culprit only runs when someone clicks a button or calls `/runs/live`. Set
`CULPRIT_SCHEDULER_ENABLED=true` to also run it unattended:

- **Scheduled** — a full cycle shortly after each maintenance window closes
  (`CULPRIT_SCHEDULED_CRON`, default nightly at 04:00).
- **Pre-flight** — a lightweight, rule-engine-only scan of the whole fleet's *current* state
  every `CULPRIT_PREFLIGHT_INTERVAL_MINUTES` (default 60), flagging machines likely to fail the
  next window while there's still time to fix them — read via `GET /culprit/preflight` or by
  asking Culprit's chat "which machines will fail next?".

Both read whatever's saved on `/culprit/settings` — no redeploy needed to point them at a
different subscription. See "Scheduling" in [culprit/RUNBOOK.md](../culprit/RUNBOOK.md) for the
full wiring, including the Teams/Slack digest and event-driven trigger.

### Agent memory (optional)

`pip install 'culprit[memory]'` and set `CULPRIT_MEMORY_ENABLED=true` to have Culprit remember
confirmed-correct root causes and use them as evidence on the next similar failure — self-hosted
only (an on-disk vector store, a local embedding model, no data leaves the host). Off by default
and a no-op without the extra installed. See "Agent memory" in
[culprit/RUNBOOK.md](../culprit/RUNBOOK.md).

---

## 5. Feature Flags (GrowthBook)

Optional. See [docs/feature-flags/README.md](feature-flags/README.md) for the full setup —
covers the Portal's launcher banners and admin-panel toggles. Culprit does not use GrowthBook.

---

## 6. Verification

- Portal API health: `https://portal.local/api/health`
- Culprit API health: `https://portal.local/culprit/health`
- Log in as the seeded admin, confirm the Culprit card appears on the launcher, and click
  through to `/culprit/` without being asked to sign in again.
