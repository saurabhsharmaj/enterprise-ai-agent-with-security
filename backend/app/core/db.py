"""Database access with tenant-scoped sessions.

Defense in depth for tenant isolation:
  1. every repository query carries an explicit `WHERE tenant_id = :tenant`;
  2. every transaction starts with `set_config('app.tenant_id', <tenant>, true)`, which activates
     PostgreSQL row-level security (policies in migration 0001). The runtime role is not the table
     owner and has no BYPASSRLS, so a forgotten WHERE clause still cannot cross tenants;
  3. OPA independently checks resource.tenant_id == subject.tenant_id.
"""
from functools import lru_cache

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    return create_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=10)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, autoflush=False)


@event.listens_for(Session, "after_begin")
def _apply_tenant_to_transaction(session: Session, transaction, connection) -> None:  # pragma: no cover - trivial
    """Runs at the start of EVERY transaction (also after commit()), so the RLS tenant is never lost."""
    tenant = session.info.get("tenant_id") or ""
    connection.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant})


def new_tenant_session(tenant_id: str) -> Session:
    """A session whose every transaction is pinned to one tenant. Caller must close() it."""
    session = get_sessionmaker()()
    session.info["tenant_id"] = tenant_id
    return session
