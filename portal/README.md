# AgentMesh Portal

The Portal is the unified entry point for the AgentMesh platform. It provides a single login page and an app launcher that gives each user access to the AI agents they are authorized to use — currently just [Culprit](../culprit/README.md).

---

## Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Login and Token Flow](#login-and-token-flow)
- [App Launcher](#app-launcher)
- [User Management](#user-management)
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
│   └── routers/apps.py           # App registry + per-user visibility
│
├── db.py                     # SQLAlchemy models + schema bootstrap + admin seed
├── security.py                # Password hashing, JWT issuance/decoding
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
│       │   └── Admin.tsx         # User management
│       ├── lib/
│       │   ├── api.ts            # fetchApps(), fetchMe(), login()
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

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://portal:portal@postgres:5432/portal` | Portal's own PostgreSQL database |
| `SECRET_KEY` | — | JWT signing secret — **must match** `CULPRIT_PORTAL_JWT_SECRET` in Culprit's config for SSO to work |
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
