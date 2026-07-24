"""Async SQLite engine and session factory.

Configures `aiosqlite` through SQLAlchemy 2's async engine, with the two
SQLite-specific settings this project depends on applied correctly:
Write-Ahead Logging (for concurrent async reads/writes without
`database is locked` errors) and foreign key enforcement (so the
`ondelete="CASCADE"` relationships in `cyberjection.persistence.models`
actually cascade).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from cyberjection.persistence.models import Base

DEFAULT_DB_URL = "sqlite+aiosqlite:///.cyberjection/results.db"


def _sqlite_file_path_from_url(db_url: str) -> Optional[Path]:
    """Extract the filesystem path from a `sqlite+aiosqlite:///path/to.db`
    URL, or None for `:memory:` / non-file URLs. Used only to make sure the
    parent directory exists before the driver tries to open the file --
    SQLite creates the database file itself but not missing parent
    directories, so a fresh checkout's first run would otherwise fail with
    `unable to open database file`."""

    if not db_url.startswith("sqlite+aiosqlite:///"):
        return None
    raw_path = db_url[len("sqlite+aiosqlite:///"):]
    if not raw_path or raw_path == ":memory:" or raw_path.startswith(":memory:"):
        return None
    return Path(raw_path)


def _register_sqlite_pragmas(engine: AsyncEngine) -> None:
    """Apply per-connection SQLite pragmas on every new DBAPI connection
    the pool opens, not just once at startup.

    This matters because SQLite pragmas fall into two categories:
    `journal_mode` is persisted in the database file itself, so setting it
    once is enough -- but `foreign_keys` and `synchronous` are per-connection
    session state that SQLite resets to its defaults (`foreign_keys` off,
    `synchronous` FULL) on every new connection. A connection pool opens
    more than one underlying connection under concurrent access, so setting
    these pragmas only inside `init_db()`'s single connection leaves every
    connection opened afterward with foreign key enforcement silently
    disabled -- meaning every `ondelete="CASCADE"` relationship in the
    schema would silently do nothing, and deleting a campaign would leave
    orphaned tests/turns/findings/metrics rows behind instead of cascading.
    Registering a `connect` event listener on the underlying sync engine
    (the standard SQLAlchemy recipe for this) re-applies the pragmas to
    every connection as it's created, closing that gap.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record) -> None:  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.close()


class DatabaseManager:
    """Manages the async SQLite connection lifecycle and session generation
    for a single database URL."""

    def __init__(self, db_url: str = DEFAULT_DB_URL, *, echo: bool = False) -> None:
        self.db_url = db_url
        self.engine = create_async_engine(
            self.db_url,
            echo=echo,
            future=True,
            connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
        )
        if "sqlite" in self.db_url:
            _register_sqlite_pragmas(self.engine)

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    @classmethod
    def in_memory(cls, *, echo: bool = False) -> "DatabaseManager":
        """Convenience factory for tests: an in-memory SQLite database
        shared across the engine's connection pool via `StaticPool`, so
        every connection sees the same in-memory data instead of each
        pooled connection getting its own empty `:memory:` database (the
        default behavior, which would make writes on one connection
        invisible to reads on another)."""

        from sqlalchemy.pool import StaticPool

        manager = cls.__new__(cls)
        manager.db_url = "sqlite+aiosqlite:///:memory:"
        manager.engine = create_async_engine(
            manager.db_url,
            echo=echo,
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        _register_sqlite_pragmas(manager.engine)
        manager.session_factory = async_sessionmaker(
            bind=manager.engine, class_=AsyncSession, expire_on_commit=False
        )
        return manager

    async def init_db(self) -> None:
        """Creates missing parent directories (for file-based SQLite),
        initializes database tables, and enables WAL mode."""

        file_path = _sqlite_file_path_from_url(self.db_url)
        if file_path is not None:
            file_path.parent.mkdir(parents=True, exist_ok=True)

        async with self.engine.begin() as conn:
            if "sqlite" in self.db_url:
                # journal_mode is persisted in the database file, so this
                # one only needs to run once; foreign_keys/synchronous are
                # also applied here for the very first connection, and by
                # the connect-event listener for every connection after.
                await conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
            await conn.run_sync(Base.metadata.create_all)

    def session(self) -> AsyncSession:
        """Return a new `AsyncSession` bound to this manager's engine."""

        return self.session_factory()

    async def close(self) -> None:
        """Gracefully closes database connections."""

        await self.engine.dispose()
