"""Alembic environment. Migrations run as the database OWNER (DATABASE_ADMIN_URL); the running API
uses the restricted `eai_app` role (DATABASE_URL) and can never alter the schema."""
import os

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config

# Plain SQL migrations: no ORM metadata needed.
target_metadata = None


def _url() -> str:
    url = os.environ.get("DATABASE_ADMIN_URL")
    if not url:
        raise RuntimeError("DATABASE_ADMIN_URL must be set to run migrations")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
