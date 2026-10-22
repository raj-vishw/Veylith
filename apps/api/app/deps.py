import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import AuthSession, Membership, Organization, User
from .security import token_hash

ROLE_RANK = {"viewer": 1, "analyst": 2, "owner": 3}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class Ctx:
    db: Session
    user: User
    org_id: uuid.UUID
    role: str
    session: AuthSession

    def can(self, role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[role]


def bind_org(db: Session, org_id: uuid.UUID) -> None:
    """Scope the open transaction and every later one on this session to a single organization."""
    db.info["org_id"] = org_id
    db.connection().exec_driver_sql("SELECT set_config('app.org_id', %s, true)", (str(org_id),))


def _check_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin not in get_settings().origins:
        raise HTTPException(status_code=403, detail="Untrusted origin")


def get_ctx(request: Request, db: Session = Depends(get_db)) -> Ctx:
    s = get_settings()
    token = request.cookies.get(s.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    sess = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(token)))
    now = datetime.now(UTC)
    if (
        sess is None
        or sess.revoked_at is not None
        or sess.expires_at <= now
        or sess.last_seen_at <= now - timedelta(minutes=s.session_idle_minutes)
    ):
        raise HTTPException(status_code=401, detail="Not authenticated")

    if request.method not in SAFE_METHODS:
        _check_origin(request)
        supplied = request.headers.get("x-csrf-token", "")
        if not secrets.compare_digest(supplied, sess.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    user = db.get(User, sess.user_id)
    # Role is read from the membership on every request, so role changes and removals apply immediately.
    membership = db.scalar(
        select(Membership).where(Membership.user_id == sess.user_id, Membership.organization_id == sess.organization_id, Membership.status == "active")
    )
    org = db.get(Organization, sess.organization_id)
    if user is None or user.status != "active" or membership is None or org is None or org.status != "active":
        raise HTTPException(status_code=401, detail="Not authenticated")

    if now - sess.last_seen_at > timedelta(minutes=1):
        sess.last_seen_at = now
        db.commit()
    bind_org(db, sess.organization_id)
    return Ctx(db=db, user=user, org_id=sess.organization_id, role=membership.role, session=sess)


def require(role: str):
    def dep(ctx: Ctx = Depends(get_ctx)) -> Ctx:
        if not ctx.can(role):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return ctx

    return dep


viewer = require("viewer")
analyst = require("analyst")
owner = require("owner")


def get_org(ctx: Ctx) -> Organization:
    org = ctx.db.get(Organization, ctx.org_id)
    assert org is not None
    return org
