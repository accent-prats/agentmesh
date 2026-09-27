from __future__ import annotations

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
