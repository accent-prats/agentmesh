"""Engine/session wiring. Defaults to a local SQLite file so the demo and
test suite need zero external setup; set CULPRIT_DATABASE_URL to point at
Postgres for a real deployment (e.g.
`postgresql+psycopg://user:pass@host/culprit`)."""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from culprit.db.models import Base

DEFAULT_URL = "sqlite:///culprit.db"


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
    return sessionmaker(bind=engine, expire_on_commit=False)
