# AgentMesh

A small demo platform pairing a unified login/app-launcher (**Portal**) with an autonomous
patch-failure RCA agent (**Culprit**), deployed as a single Docker stack.

---

## Applications

| App | Purpose | Docs |
|-----|---------|------|
| [**Portal**](portal/) | Unified login and app launcher — single set of credentials unlocks every agent a user is granted access to | [portal/README.md](portal/README.md) |
| [**Culprit**](culprit/) | Autonomous root-cause analysis for failed Azure Update Manager patch deployments — collects Azure Resource Graph, Activity Log, Datadog, and guest-OS evidence, settles obvious cases with a deterministic rule engine, and hands the ambiguous tail to Claude for deep reasoning and remediation guidance | [culprit/README.md](culprit/README.md) · [culprit/SECURITY.md](culprit/SECURITY.md) |

An already-authenticated Portal user who clicks the Culprit card is signed straight in — no
second login. See [docs/SETUP.md](docs/SETUP.md) for first-time configuration.

---

## Repository Structure

```
.
├── .mcp.json.template        # Claude Code MCP server config template (postgres, filesystem, fetch)
├── docker-compose.yml        # Full unified stack (all services, one command)
├── .env.example              # All environment variables with defaults
│
├── portal/                   # Unified login + app launcher
│   ├── api/                  # FastAPI backend (auth, app registry, user management)
│   ├── ui/                   # React + Vite + Tailwind frontend (login, app launcher, admin)
│   ├── db.py                 # SQLAlchemy models + schema bootstrap + admin seed
│   ├── security.py           # Password hashing, JWT issuance/decoding
│   └── Dockerfile
│
├── culprit/                  # Autonomous Azure Update Manager patch-failure RCA agent
│   ├── culprit/api/          # FastAPI routers (runs, settings, webhooks, auth)
│   ├── culprit/collectors/   # Azure Resource Graph/Activity Log/Monitor, Datadog, guest OS
│   ├── culprit/pipeline/     # Clustering, rule engine, Claude-backed RCA agent, orchestrator
│   ├── culprit/security/     # Portal JWT validation, credential encryption, scrubbing, RBAC
│   ├── culprit/reporting/    # Server-rendered console/settings UI
│   └── Dockerfile
│
├── shared/                   # Shared library — imported by both apps
│   └── src/
│       ├── feature_flags/    # GrowthBook client + FastAPI middleware (used by Portal)
│       └── llm/              # Multi-provider AI client construction (used by Culprit's
│                             # deep RCA agent; app-agnostic, see shared/README.md)
│
├── infrastructure/
│   ├── nginx/                 # Reverse proxy configs + TLS cert generation
│   └── mongodb/               # GrowthBook's MongoDB config
│
├── scripts/
│   └── deploy.sh              # First-time and incremental deployment script
│
└── docs/                      # Administrator Setup Guide, feature-flag guide
```

---

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env          # fill in API keys and secrets

# 2. Generate TLS certs + deploy everything (first time)
bash scripts/deploy.sh

# 3. Add a hosts entry (one-time, requires admin/sudo)
# Windows: C:\Windows\System32\drivers\etc\hosts
# Linux/macOS: /etc/hosts
#   127.0.0.1  portal.local
```

Access:
- **Portal (login):** https://portal.local
- **Culprit:** https://portal.local/culprit/ (via the app launcher, once granted access)

For incremental re-deploys (skip full rebuild):
```bash
bash scripts/deploy.sh --update
```

See [docs/SETUP.md](docs/SETUP.md) for the first-login admin account, granting Culprit access
to other users, and configuring Culprit's Azure/Datadog connections.

---

## Authentication Architecture

Portal and Culprit share a single JWT signing secret (`SECRET_KEY` in Portal, `CULPRIT_PORTAL_JWT_SECRET`
in Culprit — set both to the same value). A token issued by Portal is valid in Culprit without
any token exchange.

**Login flow:**
1. User logs in at `portal.local` → Portal API validates credentials against its own `users` table
2. Portal issues a JWT containing an `app_access` claim listing the apps the user can launch
3. Clicking the Culprit card appends `?auth_token=<jwt>` to Culprit's URL
4. Culprit validates the token, converts it into its own session cookie, and drops the query
   param from the URL bar

**Session lifetime is sliding, not fixed:** Culprit re-signs and re-sets that cookie (same claims,
a fresh expiry) on every request while it's still valid, so an actively-browsing user's session
lasts "since your last click," not "since you logged in." The shared `CULPRIT_API_TOKEN` and a
script's `Authorization: Bearer` header are never renewed this way — see
[culprit/SECURITY.md](culprit/SECURITY.md#sliding-session-renewal-2026-09-27) for the full design
and its deliberate scope.

See [portal/README.md](portal/README.md#login-and-token-flow) and
[culprit/SECURITY.md](culprit/SECURITY.md) for the full details on each side.

---

## Platform-Wide AI Configuration

Which LLM an agent calls (Culprit's deep RCA agent today) is configured once, for the whole
platform, from **Portal's Admin → AI Providers** screen — not per-app, and with no default
provider until an admin picks one. See [portal/README.md#ai-providers](portal/README.md#ai-providers)
for the admin-facing picture and [shared/README.md](shared/README.md) for the adapter package
every consuming app builds a client from.

---

## Claude Code MCP Setup

A `.mcp.json.template` is included at the repo root. Copy it to `.mcp.json`, fill in your DB
password, and restart Claude Code to get postgres/filesystem/fetch MCP servers wired up
automatically.

---

## Contributing

1. Run `pytest` in the affected app directory (`portal/` or `culprit/`) before opening a PR
2. All structured logging uses `structlog` — `get_logger(__name__)` from `portal/logging_config.py`
3. Docker images use an Alpine base with two-stage builds to minimize CVE surface
