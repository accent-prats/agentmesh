# Feature Flagging — GrowthBook

> Self-hosted, open-source feature flagging and A/B experimentation for the AgentMesh platform.

---

## Quick Links

| What | Where |
|---|---|
| **Admin UI** | `https://growthbook.local` |
| **SDK API** (internal) | `http://growthbook:3101` |
| **Python SDK module** | [shared/src/feature_flags/](../../shared/src/feature_flags/) |
| **Docker service** | `growthbook` in [docker-compose.yml](../../docker-compose.yml) |

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [First-Time Setup](#first-time-setup)
3. [Flag Naming Convention](#flag-naming-convention)
4. [User Targeting Attributes](#user-targeting-attributes)
5. [Using Flags — Backend (Python)](#using-flags--backend-python)
6. [Using Flags — Frontend (React)](#using-flags--frontend-react)
7. [Adding a New Flag — Step by Step](#adding-a-new-flag--step-by-step)
8. [Architecture Notes](#architecture-notes)
9. [Troubleshooting](#troubleshooting)

---

## How It Works

```
┌─────────────────────────────────────────────────────┐
│  GrowthBook Admin UI (growthbook.local)             │
│  Define flags, targeting rules, experiments         │
└──────────────────────┬──────────────────────────────┘
                       │ SDK API (port 3101)
                       ▼
                  Portal API
                 (Python SDK)
                       │
                  FlagMiddleware
                  ── per request ──
                  builds user attributes from JWT
                  evaluates flags in-memory (no network call)
                  attaches result to request.state.flags
                       │
                  Any router can call:
                  flags.is_on("portal.admin.bulk-user-import")

                    ┌─────────────┐
                    │  Portal UI  │
                    │ (React SDK) │
                    └─────────────┘
                    GrowthBookProvider wraps the app root.
                    useFeatureIsOn() / useFeatureValue() in any component.
```

Only the Portal integrates GrowthBook today — Culprit doesn't use it, and has no
`FlagMiddleware`/`GrowthBookProvider` wiring of its own.

**Key properties:**
- Flag definitions are fetched from GrowthBook on startup and **refreshed every 60 seconds** in the background.
- All evaluation is **in-memory** — zero per-request network latency.
- If GrowthBook is **unreachable** (container down, network issue), every flag returns its configured default value. The app keeps running normally.

---

## First-Time Setup

### 1. Start GrowthBook

```bash
docker compose up -d growthbook
```

Wait ~15 seconds, then open `https://growthbook.local` and create your admin account.

### 2. Create SDK Connection

1. GrowthBook Admin → **SDK Connections** → **Add Connection**
2. Name: `AgentMesh Platform`, Environment: `Production`
3. Copy the generated `sdk-xxxxxxxxxx` key

### 3. Add the SDK key to your environment

In `.env` (root):
```env
GROWTHBOOK_CLIENT_KEY=sdk-xxxxxxxxxx
```

In `portal/ui/.env` (copy from `.env.example`):
```env
VITE_GROWTHBOOK_CLIENT_KEY=sdk-xxxxxxxxxx
VITE_GROWTHBOOK_API_HOST=http://localhost:3101
```

### 4. Define Targeting Attributes

GrowthBook Admin → **Attributes** → add these (matches what `FlagMiddleware` sends):

| Attribute | Type | Example |
|---|---|---|
| `id` | String | `"a1b2c3d4-..."` |
| `email` | String | `"jane@example.com"` |
| `role` | Enum | `admin`, `user`, `read_only`, `ci_service` |
| `app_access` | String[] | `["culprit"]` |
| `app` | Enum | `portal` |
| `company` | String | `"example.com"` |
| `environment` | Enum | `development`, `staging`, `production` |

### 5. Restart the stack

```bash
docker compose restart portal-api
```

---

## Flag Naming Convention

```
{app}.{component}.{feature-name}
```

| Flag | Type | Purpose |
|---|---|---|
| `portal.admin.bulk-user-import` | Boolean | Shows the (not-yet-implemented) CSV user import panel in Admin |
| `portal.launcher.maintenance-banner` | Boolean | Amber "scheduled maintenance" banner on the app launcher |
| `shared.maintenance.readonly-mode` | Boolean | Red "read-only mode" banner on the app launcher |
| `shared.beta.early-access` | Boolean | "Early Access" badge on the launcher hero strip |

**Rules:**
- Always use kebab-case for the feature name.
- Prefix with `shared.` only for flags that could apply platform-wide, even though only Portal reads them today.

---

## User Targeting Attributes

These are derived automatically from the JWT and injected by `FlagMiddleware` on every request — no manual work needed.

```python
# What FlagMiddleware sends to GrowthBook for a human user:
{
    "id":         "a1b2c3d4-...",         # user UUID
    "email":      "jane@example.com",
    "role":       "admin",                # admin | user | read_only | ci_service
    "app_access": ["culprit"],
    "app":        "portal",               # which backend service handled the request
    "company":    "example.com",          # extracted from email domain
    "environment": "production",
}
```

### Useful targeting rules you can configure in GrowthBook

| Goal | Rule |
|---|---|
| Dogfood with internal team only | `email` contains `@example.com` |
| Admins only | `role` = `admin` |
| Gradual rollout | Percentage rollout (0 → 10 → 50 → 100%) |
| Staging only | `environment` = `staging` |
| Specific user | `email` = `jane@example.com` |

---

## Using Flags — Backend (Python)

### In any FastAPI router

```python
from growthbook import GrowthBook
from fastapi import Depends
from shared.src.feature_flags import get_feature_flags

@router.get("/something")
async def get_something(
    flags: GrowthBook = Depends(get_feature_flags),
    user = Depends(get_current_user),
):
    if flags.is_on("portal.admin.bulk-user-import"):
        ...
```

### Flag evaluation falls back silently

If GrowthBook is unreachable, `get_feature_flags()` returns an empty `GrowthBook()` instance where:
- `is_on(key)` → `False`
- `get_feature_value(key, default)` → `default`

Your code never needs to handle the "GrowthBook down" case explicitly.

---

## Using Flags — Frontend (React)

### In any component

```tsx
import { useFeatureIsOn } from '@growthbook/growthbook-react'

export function AppLauncher() {
  const maintenanceBanner = useFeatureIsOn('portal.launcher.maintenance-banner')

  return maintenanceBanner ? <MaintenanceBanner /> : null
}
```

### The provider is already wired

`GrowthBookProvider` wraps the root of the Portal app in `App.tsx`. No setup needed per component — just import the hooks and use them.

### User attributes update on login

`createGrowthBook()` in `portal/ui/src/lib/growthbook.ts` reads the JWT from `localStorage` at startup. If the user logs in mid-session, call `gb.setAttributes(buildAttributes())` to refresh targeting context.

---

## Adding a New Flag — Step by Step

1. **Define in GrowthBook Admin UI**
   - Follow the naming convention: `{app}.{component}.{feature-name}`
   - Set a safe `off` / `false` / `""` default
   - Add targeting rules if needed (e.g. admins only for initial rollout)

2. **Use in backend router** (if backend-controlled)
   ```python
   flags: GrowthBook = Depends(get_feature_flags)
   if flags.is_on("portal.my-component.my-feature"):
       ...
   ```

3. **Use in React component** (if UI-controlled)
   ```tsx
   const enabled = useFeatureIsOn('portal.my-component.my-feature')
   ```

4. **Test with your own account first**
   - Add a rule: `email = your@email.com → on`
   - Verify the feature works, then expand to a % rollout

5. **Graduate to 100%** once stable, then remove the flag check from code and archive the flag in GrowthBook.

---

## Architecture Notes

### What GrowthBook stores (MongoDB)
- Feature flag definitions, rules, and targeting conditions
- Experiment configurations and variant assignments
- Audit history of flag changes

### Flag refresh cycle
- Backend: features polled every `GROWTHBOOK_REFRESH_INTERVAL` seconds (default: 60)
- Frontend: features polled on init in polling mode (compatible with self-hosted GrowthBook)
- Changes in GrowthBook Admin take effect within 60 seconds — no restarts needed

---

## Troubleshooting

### All flags returning defaults / `is_on()` always `False`

1. Check `GROWTHBOOK_CLIENT_KEY` is set and starts with `sdk-`:
   ```bash
   docker compose exec portal-api env | grep GROWTHBOOK
   ```
2. Verify GrowthBook is running:
   ```bash
   docker compose ps growthbook
   curl http://localhost:3101/api/features/sdk-your-key-here
   ```
3. Check Portal logs for `growthbook_fetch_failed`:
   ```bash
   docker compose logs portal-api | grep growthbook
   ```

### TypeScript errors in IDE (`Cannot find module '@growthbook/growthbook-react'`)

Run `npm install` inside `portal/ui` — the package is declared in `package.json` but not yet installed locally.

### Flag works in backend but not in UI (or vice versa)

Backend and frontend are separate SDK instances. Each independently fetches flag definitions from GrowthBook. Check:
- `VITE_GROWTHBOOK_CLIENT_KEY` is set in `portal/ui/.env`
- `VITE_GROWTHBOOK_API_HOST` is reachable from the browser (`http://localhost:3101` for local dev)
