# AgentMesh Portal

The Portal is the unified entry point for the AgentMesh platform. It provides a single login page and an app launcher that gives each user access to the AI agents they are authorized to use — currently just [Culprit](../culprit/README.md).

---

## Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Login and Token Flow](#login-and-token-flow)
- [App Launcher](#app-launcher)
- [User Management](#user-management)
- [AI Providers](#ai-providers)
- [Configuration](#configuration)
- [Docker](#docker)

---

## How It Works

```
User visits portal.local
        ↓
  Login page (AgentMesh)
  Authenticates against the Portal's own users table
        ↓
  JWT issued with app_access claims
  AppLauncher shows authorized agent cards
        ↓
  Click card → ?auth_token=<jwt> appended to app URL
  Target app (Culprit) accepts the token and strips it from the URL bar
```

No per-app login. One set of credentials unlocks every authorized agent.

---

## Architecture

```
portal/
├── api/                      # FastAPI backend (port 8000)
│   ├── main.py                   # App setup, GrowthBook flags, DB bootstrap
│   ├── routers/auth.py           # Login, refresh, user/app-access management
│   ├── routers/apps.py           # App registry + per-user visibility
│   └── routers/ai_providers.py   # Platform-wide AI provider config (admin) +
│                                  # the service-to-service resolved-active endpoint
│
├── db.py                     # SQLAlchemy models + schema bootstrap + admin seed
│                              # (User, AIProviderSetting)
├── security.py                # Password hashing, JWT issuance/decoding,
│                                # create_service_token() for app-to-app calls
├── crypto.py                  # Fernet encryption for AI provider secrets
│                                # (PORTAL_ENCRYPTION_KEY - a separate key from
│                                # any consuming app's own encryption)
│
├── ui/                        # React + Vite + TypeScript + Tailwind CSS
│   ├── public/
│   │   ├── logo-white.svg
│   │   ├── logo-dark.svg
│   │   └── favicon.svg
│   └── src/
│       ├── pages/
│       │   ├── Login.tsx         # Sign-in page
│       │   ├── AppLauncher.tsx   # App grid with role-based card visibility
│       │   └── Admin.tsx         # User Management + AI Providers tabs
│       ├── lib/
│       │   ├── api.ts            # fetchApps(), fetchMe(), login(), getAIProviders()/saveAIProvider()/...
│       │   └── auth.ts           # saveTokens(), clearTokens(), buildAppUrl()
│       └── main.tsx
│
├── Dockerfile                 # Two-stage Alpine build (python:3.12-alpine)
└── requirements.txt
```

---

## Login and Token Flow

### 1. Authentication

The Portal API validates credentials against its own `users` table and issues a JWT containing:

```json
{
  "sub": "<user-uuid>",
  "role": "admin | user",
  "app_access": ["culprit"],
  "exp": "<timestamp>"
}
```

### 2. Token storage

The Portal UI stores `access_token` and `refresh_token` in `localStorage`.

### 3. Launching an app

`buildAppUrl(app.url)` appends `?auth_token=<access_token>` to the app's base URL:

```
https://portal.local/culprit/?auth_token=eyJhbGci...
```

### 4. Token acceptance in the target app

Culprit validates the JWT (same signing secret, `CULPRIT_PORTAL_JWT_SECRET`) on its first request, converts it into its own session cookie, and drops the query param from the URL bar. The user never sees a second login page.

---

## App Launcher

The AppLauncher page (`/`) shows one card per app the user has access to. Cards are hidden for apps not listed in the user's `app_access` claim.

| ID | Name | Type | Notes |
|----|------|------|-------|
| `culprit` | Culprit | RCA Agent | Autonomous root-cause analysis for failed Azure Update Manager patch deployments |

**Admin users** always see every registered app regardless of their own `app_access` list (`apps.py::list_accessible_apps`), and see a Settings link in the header that navigates to `/admin`.

---

## User Management

Users live in the Portal's own `users` table (see `portal/db.py`) — Culprit has no user database of its own and trusts the Portal's JWT.

**Roles:**
- `admin` — full access to every app + the admin panel, regardless of their own `app_access` list
- `ci_service` — same all-apps bypass as `admin`, intended for scripted/CI callers
- `user` — access limited to the apps listed in their `app_access` claim
- `read_only` — reserved for future use

Grant or revoke Culprit access for a user from **Admin → User Management** — no DB access needed.

A first admin account is seeded automatically on first startup if the `users` table is empty (see [Configuration](#configuration) for the env vars that control its email/password).

---

## AI Providers

**Admin → AI Providers** configures which LLM a consuming app's AI agent calls — Culprit's deep
RCA agent today, any future app tomorrow. This is deliberately a **platform-wide** setting, not a
per-app one: it lives in Portal's own `AIProviderSetting` table (`portal/db.py`), not in the
consuming app's database, so a second app added later gets the same admin screen and the same
provider catalog for free instead of re-implementing this.

**Catalog:** Anthropic, OpenAI, Azure OpenAI, Google Gemini, xAI Grok, Alibaba Qwen, DeepSeek,
Ollama, and LM Studio (`shared/src/llm/catalog.py` — a shared module, not Portal's own code, so
adding a provider is one edit every consuming app picks up automatically). DeepL is deliberately
absent — it's a translation API with no tool-calling capability, so it can't run an agent that
needs one.

**No default provider.** Until an admin picks one and marks it active, `active_provider` is empty
and every consuming app falls back to whatever it did before this screen existed (Culprit:
`ANTHROPIC_API_KEY`). **Clear active provider** returns to that same "nothing configured" state
deliberately — an admin can always step back to the pre-existing fallback, not just forward.

**Two audiences, two trust models on the same data:**
- The admin screen itself (`GET/PUT /api/ai-providers*`) — a human admin, gated by
  `require_admin`, same as User Management. Secrets are never echoed back, only whether one is
  configured (`api_key_configured: bool`).
- `GET /api/ai-providers/resolved-active` — the *only* endpoint that returns a decrypted key, and
  only to another app's backend calling in at request time to actually build a client, gated by
  `require_service` (a short-lived `type: "service"` token that app mints itself with the shared
  Portal-SSO secret, never a real user session). See [culprit/SECURITY.md](../culprit/SECURITY.md#ai-provider-credentials-platform-wide-owned-by-portal)
  for the full trust-boundary writeup.

The real model call happens directly from the consuming app to the provider — Portal resolves
"which credential" once per run and is never in the request path for the actual prompt/response.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://portal:portal@postgres:5432/portal` | Portal's own PostgreSQL database |
| `SECRET_KEY` | — | JWT signing secret — **must match** `CULPRIT_PORTAL_JWT_SECRET` in Culprit's config for SSO to work |
| `PORTAL_ENCRYPTION_KEY` | insecure dev-only default | Encrypts AI provider secrets saved on Admin → AI Providers at rest (Fernet, `portal/crypto.py`) — set a real value before saving any real provider API key |
| `PORTAL_ADMIN_EMAIL` | `admin@example.com` | Email for the auto-seeded first admin account |
| `PORTAL_ADMIN_PASSWORD` | `ChangeMe123!` | Password for the auto-seeded first admin account — change this before any real deployment |
| `GROWTHBOOK_API_HOST` | `http://growthbook:3100` | Internal GrowthBook SDK API URL |
| `GROWTHBOOK_CLIENT_KEY` | `sdk-` | GrowthBook SDK connection key |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warning` \| `error` |

The seeded admin credentials are a **development convenience only** — rotate the password (or set `PORTAL_ADMIN_PASSWORD` before first startup) in any deployment that isn't a throwaway demo.

---

## Docker

```bash
# From repo root — start everything:
docker compose up -d

# Rebuild only the portal:
docker compose build portal-api portal-ui
docker compose up -d portal-api portal-ui
```

The Portal creates its own schema and seeds its first admin user on startup (`portal/db.py::bootstrap`) — no separate migration step is required.

**Ports (internal Docker network):**
- Portal API: `8000`
- Culprit API: `8090`

Both are exposed to users via the nginx reverse proxy on `portal.local`.
