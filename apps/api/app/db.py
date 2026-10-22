import uuid
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings

engine = create_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=10)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


@event.listens_for(Session, "after_begin")
def _apply_tenant_context(session, transaction, connection):
    """Bind the transaction to the caller's organization so PostgreSQL row-level
    security can enforce isolation even if an application query forgets a filter.
    With no organization set the policies match no rows (fail closed)."""
    org_id = session.info.get("org_id")
    connection.exec_driver_sql("SELECT set_config('app.org_id', %s, true)", (str(org_id) if org_id else "",))


def get_db():
    with SessionLocal() as db:
        yield db


@contextmanager
def org_session(org_id: uuid.UUID):
    """Session scoped to one organization, for background jobs."""
    with SessionLocal() as db:
        db.info["org_id"] = org_id
        yield db
