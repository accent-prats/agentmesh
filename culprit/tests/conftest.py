from __future__ import annotations

import os

# Must run before anything below (even the sys.path tweak) can transitively
# import culprit.config - Settings.demo_enabled reads this env var once, at
# Settings() construction time, the same moment culprit.config is first
# imported anywhere in the process. demo_enabled defaults to False in
# actual deployments now (flipped 2026-10-14, opt-in instead of opt-out,
# so a deployment nobody configured as a demo environment doesn't silently
# expose one) - but the overwhelming majority of this suite calls
# POST /runs/demo and relies on it working with zero per-test
# configuration (see tests/test_demo_gating.py's own tests for the real,
# opt-out-free default). setdefault, not a hard set, so an individual
# test can still override it via monkeypatch.setattr(config, "settings", ...)
# exactly as several already do.
os.environ.setdefault("CULPRIT_DEMO_ENABLED", "true")

import sys
from pathlib import Path

import pytest

# Mirrors the Dockerfile's PYTHONPATH for a deployed container (which
# copies shared/ next to culprit/ and sets PYTHONPATH=/app/culprit:/app) -
# `shared.src.llm` (the multi-provider AI adapters Culprit's RCA agent
# calls through) lives one level up from this repo's culprit/ directory,
# which isn't on sys.path when pytest runs from inside culprit/.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from culprit.db.engine import make_engine, make_session_factory


@pytest.fixture
def session_factory():
    """A fresh in-memory SQLite DB per test - no shared state between
    tests, no file left on disk."""
    engine = make_engine("sqlite:///:memory:")
    return make_session_factory(engine)
