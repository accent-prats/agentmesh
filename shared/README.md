# shared — Common Library

Code shared across the platform's backend services. Import directly — this is not a
packaged library, it lives in the monorepo and is resolved via `PYTHONPATH`.

---

## Contents

```
shared/src/
└── feature_flags/
    ├── __init__.py
    ├── client.py         # GrowthBookClient — wraps the GrowthBook Python SDK
    ├── dependencies.py   # get_feature_flags() FastAPI dependency
    └── middleware.py     # FlagMiddleware — builds per-request user attributes
```

---

## Feature Flags (`shared/src/feature_flags/`)

Used today by Portal. See [docs/feature-flags/README.md](../docs/feature-flags/README.md) for
the full setup and usage guide — this section is just the import surface.

```python
from shared.src.feature_flags import FlagMiddleware, GrowthBookClient, set_client, get_feature_flags
```

- `GrowthBookClient` / `set_client` / `get_client` — initialized once at app startup (see
  `portal/api/main.py`'s lifespan handler), polls GrowthBook for flag definitions in the background.
- `FlagMiddleware` — added to the FastAPI app, builds the per-request user attribute dict
  (from the JWT) that GrowthBook targeting rules match against.
- `get_feature_flags` — a FastAPI dependency any router can use to read `request.state.flags`.

---

## Import paths

For local development outside Docker, either set `PYTHONPATH` manually or run from the repo root:

```bash
PYTHONPATH=. python -m uvicorn portal.api.main:app --reload
```
