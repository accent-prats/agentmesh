"""culprit/requirements.txt must actually install a driver for
CULPRIT_DATABASE_URL's postgresql+psycopg:// scheme.

Found live 2026-11-22, via a real deployment's own Application Insights
trace: discover_run_activity's own create_engine(settings.database_url)
call raised `ModuleNotFoundError: No module named 'psycopg'` the moment a
real Postgres CULPRIT_DATABASE_URL was actually set on the serverless
Function App - requirements.txt never needed a Postgres driver before,
since the default (and only previously-exercised) Docker Compose
deployment uses sqlite:///culprit.db (culprit/config.py's own default).

This is a real behavioral check, not just a string match on
requirements.txt - it actually calls SQLAlchemy's create_engine() with
the exact dialect+driver string this codebase uses, the same call that
failed in production, and asserts it no longer raises. It cannot (and
does not try to) prove a real network connection succeeds - create_engine
is lazy and never connects on its own - only that the driver is
importable and the dialect resolves, which is exactly as far as the
production failure got.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine

_REQUIREMENTS = Path(__file__).resolve().parent.parent / "requirements.txt"


def test_psycopg_is_listed_in_requirements_txt():
    text = _REQUIREMENTS.read_text(encoding="utf-8")
    assert "psycopg" in text, (
        "psycopg (v3) must be installed for CULPRIT_DATABASE_URL's "
        "postgresql+psycopg:// scheme to resolve - see this file's own "
        "docstring for the real production failure this guards against"
    )


def test_create_engine_resolves_the_postgresql_psycopg_dialect():
    """The exact call that failed in production (culprit/db/engine.py::
    make_engine -> create_engine(url)), with a fake, unreachable host -
    this never connects, it only needs the driver to actually import."""
    engine = create_engine("postgresql+psycopg://user:pass%237@fake-host.invalid/culprit")
    assert engine.dialect.driver == "psycopg"
