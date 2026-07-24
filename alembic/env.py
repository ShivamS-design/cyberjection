"""Alembic environment: async-engine-compatible migration runner.

Alembic's online-migration path (`run_migrations_online`) is written around
a synchronous DBAPI connection, but every other database access in this
project goes through `cyberjection.persistence.sqlite.DatabaseManager`,
which uses SQLAlchemy's async engine (`aiosqlite`). Building a second,
synchronous engine here just for migrations would mean two separate
connection code paths -- including two places to apply the
`PRAGMA foreign_keys` / `PRAGMA synchronous` per-connection fix documented
in `cyberjection/persistence/sqlite.py` -- that would need to be kept in
sync by hand. Instead, this driver builds the same async engine and runs
the synchronous migration context through `connection.run_sync(...)` inside
`asyncio.run(...)`, so there is exactly one connection code path.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from cyberjection.persistence.models import Base
from cyberjection.persistence.sqlite import DEFAULT_DB_URL

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# CYBERJECTION_DB_URL takes precedence over alembic.ini's static default so
# migrations run against the same database the application is configured
# for, not a hardcoded path.
db_url = os.environ.get("CYBERJECTION_DB_URL", DEFAULT_DB_URL)
config.set_main_option("sqlalchemy.url", db_url)


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live DB connection, e.g.
    `alembic upgrade head --sql`."""

    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
