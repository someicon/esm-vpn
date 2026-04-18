from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings
from app.db.models import Base


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine() -> AsyncEngine:
    settings = get_settings()
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    return create_async_engine(
        settings.db_url,
        echo=False,
        future=True,
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _session_factory


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _apply_lightweight_migrations(conn)


async def _apply_lightweight_migrations(conn) -> None:
    """Add columns introduced after the initial schema.

    SQLite doesn't support `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so we
    inspect the table and add missing columns ourselves. Keeps the project
    free of a full migration framework (Alembic) while still letting existing
    DBs upgrade in place on the next start.
    """
    result = await conn.exec_driver_sql("PRAGMA table_info(peers)")
    existing = {row[1] for row in result.fetchall()}
    if "last_handshake_at" not in existing:
        await conn.exec_driver_sql(
            "ALTER TABLE peers ADD COLUMN last_handshake_at DATETIME"
        )
