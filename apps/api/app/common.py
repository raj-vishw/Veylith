import uuid
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .deps import Ctx


class Page(BaseModel):
    items: list[Any]
    total: int
    limit: int
    offset: int


def paginate(db: Session, stmt, limit: int, offset: int, serialize) -> dict:
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    rows = db.scalars(stmt.limit(limit).offset(offset)).all()
    return {"items": [serialize(r) for r in rows], "total": total, "limit": limit, "offset": offset}


def get_owned(ctx: Ctx, model, object_id: uuid.UUID, *, allow_deleted: bool = False):
    """Fetch a row that must belong to the caller's organization. Anything else is a 404, so the
    existence of other tenants' records is not revealed. Row-level security backs this up in the database."""
    obj = ctx.db.get(model, object_id)
    if obj is None or obj.organization_id != ctx.org_id:
        raise HTTPException(status_code=404, detail=f"{model.__name__} not found")
    if not allow_deleted and getattr(obj, "deleted_at", None) is not None:
        raise HTTPException(status_code=404, detail=f"{model.__name__} not found")
    return obj


def as_dict(obj, fields: list[str]) -> dict:
    return {f: getattr(obj, f) for f in fields}


LEVELS = ("low", "medium", "high", "critical")
