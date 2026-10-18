"""Engine/session wiring. Defaults to a local SQLite file so the demo and
test suite need zero external setup; set CULPRIT_DATABASE_URL to point at
Postgres for a real deployment (e.g.
`postgresql+psycopg://user:pass@host/culprit`)."""
from __future__ import annotations

import logging
import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from culprit.db.models import Base

log = logging.getLogger(__name__)

DEFAULT_URL = "sqlite:///culprit.db"

# (table, column, SQL type) pairs added to an existing table after it first
# shipped. `Base.metadata.create_all()` only ever creates *missing tables* -
# it never alters a table that already exists, so a column added here in
# code would silently never reach an already-deployed SQLite file (the
# first write to it would fail with "no such column"). SQLite supports
# `ALTER TABLE ... ADD COLUMN` directly, so _ensure_columns() checks each
# one via `PRAGMA table_info` and adds it if missing - this is deliberately
# scoped to the exact columns known to need it, not a general migration
# framework (this app has no migration tooling for Postgres either; a real
# Postgres deployment needs a real migration tool before this grows).
_ADDED_COLUMNS: list[tuple[str, str, str]] = [
    ("machine_outcomes", "patch_extension_status_json", "JSON"),
    ("machine_outcomes", "error_details_json", "JSON"),
    ("machine_outcomes", "timeline_json", "JSON"),
    ("runs", "created_at", "DATETIME"),
]


def _ensure_columns(engine) -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    with engine.begin() as conn:
        for table, column, sql_type in _ADDED_COLUMNS:
            existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            if not existing:
                continue  # table doesn't exist yet - create_all() will make it with the column already present
            if column not in existing:
                log.info("Adding column %s.%s (existing database predates it)", table, column)
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}"))


def make_engine(url: str | None = None):
    url = url or os.environ.get("CULPRIT_DATABASE_URL", DEFAULT_URL)
    if not url.startswith("sqlite"):
        return create_engine(url)
    # SQLite specifics: allow cross-thread use (the collection fan-out uses
    # a thread pool), and for the in-memory URL - test suite default - pin
    # every connection to the same in-process database via StaticPool, or
    # each new session would otherwise see a brand-new, empty :memory: DB.
    connect_args = {"check_same_thread": False}
    if ":memory:" in url:
        return create_engine(url, connect_args=connect_args, poolclass=StaticPool)
    return create_engine(url, connect_args=connect_args)


def make_session_factory(engine=None) -> sessionmaker[Session]:
    engine = engine or make_engine()
    Base.metadata.create_all(engine)
    _ensure_columns(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
