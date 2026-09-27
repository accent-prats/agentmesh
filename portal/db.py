"""
Portal database session and models.
"""
import os
import uuid

from sqlalchemy import Boolean, Column, DateTime, String, func, select
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://portal:portal@postgres:5432/portal",
)

engine = create_async_engine(DATABASE_URL, pool_size=5, max_overflow=10, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email           = Column(String(255), unique=True, nullable=False)
    full_name       = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role            = Column(String(20), nullable=False, default="user")
    is_active       = Column(Boolean, default=True, nullable=False)
    app_access      = Column(JSONB, nullable=False, default=list)
    created_at      = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at      = Column(DateTime(timezone=True), onupdate=func.now())


class AIProviderSetting(Base):
    """Platform-wide AI provider configuration - admin-managed here, read
    by every app that needs an LLM call (Culprit's deep RCA agent today,
    any future app tomorrow) instead of each one having its own copy.

    One row per catalog provider (shared/src/llm/catalog.py), keyed by
    provider id, plus a single row keyed "__active__" naming which one is
    currently selected - there is deliberately no default: until an admin
    picks one on the AI Providers screen, `active_provider` is empty and
    every app falls back to whatever it did before this table existed
    (Culprit: its own ANTHROPIC_API_KEY env var, unchanged).

    `data_json` holds plain-text fields as-is and `api_key` as Fernet
    ciphertext (portal/crypto.py) - only this table's own reader/writer
    (portal/api/routers/ai_providers.py) ever decrypts it; another app
    receives an already-decrypted value over the authenticated
    resolved-active endpoint, never the ciphertext itself.
    """
    __tablename__ = "ai_provider_settings"

    provider          = Column(String(64), primary_key=True)
    data_json         = Column(JSONB, nullable=False, default=dict)
    last_tested_at    = Column(DateTime(timezone=True), nullable=True)
    last_test_ok      = Column(Boolean, nullable=True)
    last_test_message = Column(String, nullable=False, default="")


async def get_db():
    async with AsyncSessionLocal() as session:
        async with session.begin():
            yield session


async def bootstrap() -> None:
    """Create the schema if it doesn't exist yet and seed a first admin
    account so a freshly-started deployment isn't locked out. Safe to call
    on every startup — both steps are no-ops once they've run once.

    The Portal container runs multiple uvicorn workers (see Dockerfile),
    each of which runs this same lifespan startup independently, so two
    workers can both see an empty schema and race each other. The seed
    insert's own race is caught explicitly below (an IntegrityError on the
    losing worker's duplicate email).

    Found while adding `AIProviderSetting` (2026-09-27): `create_all()`
    itself is *not* actually race-safe against a real concurrent
    Postgres, despite `checkfirst=True` being the default - two workers
    can both see a table missing and both issue `CREATE TABLE`, and
    Postgres's own catalog (`pg_type`) throws a `UniqueViolationError` for
    the loser, crashing that worker's startup outright (it only survived
    before this because nothing had added a *new* table since the schema
    was first created, so the create-vs-race window mattered only once,
    at first boot - deploys since then always saw the whole schema
    already exist). Caught the same way as the seed-insert race below.
    """
    from sqlalchemy.exc import IntegrityError

    from portal.security import hash_password

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except IntegrityError:
        # Another worker's CREATE TABLE won the race - the schema exists
        # either way, which is all this call is for.
        pass

    async with AsyncSessionLocal() as session:
        try:
            async with session.begin():
                existing = await session.execute(select(User).limit(1))
                if existing.scalar_one_or_none() is not None:
                    return
                admin_email = os.environ.get("PORTAL_ADMIN_EMAIL", "admin@example.com")
                admin_password = os.environ.get("PORTAL_ADMIN_PASSWORD", "ChangeMe123!")
                session.add(User(
                    email=admin_email,
                    full_name="Admin",
                    hashed_password=hash_password(admin_password),
                    role="admin",
                    is_active=True,
                    app_access=["culprit"],
                ))
        except IntegrityError:
            # Another worker won the race and already seeded this email -
            # session.begin() has already rolled back the failed transaction.
            pass
