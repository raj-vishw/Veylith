import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..common import paginate
from ..deps import Ctx, analyst, owner, viewer
from ..models import (
    AuditEvent,
    AuthSession,
    ChangeEvent,
    Membership,
    Organization,
    User,
    utcnow,
)
from ..security import hash_password
from ..services import audit

router = APIRouter(tags=["organization"])

ROLES = ("owner", "analyst", "viewer")


class OrgPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    slug: str | None = Field(default=None, min_length=2, max_length=100, pattern="^[a-z0-9]+(-[a-z0-9]+)*$")
    timezone: str | None = Field(default=None, max_length=64)
    retention_days: int | None = Field(default=None, ge=30, le=3650)


class MemberIn(BaseModel):
    email: EmailStr
    password: str | None = Field(default=None, min_length=12, max_length=200)  # required for new accounts
    display_name: str = Field(default="", max_length=200)
    role: str = Field(pattern="^(owner|analyst|viewer)$")


class MemberPatch(BaseModel):
    role: str = Field(pattern="^(owner|analyst|viewer)$")


def _org(o: Organization) -> dict:
    return {
        "id": o.id,
        "name": o.name,
        "slug": o.slug,
        "status": o.status,
        "timezone": o.timezone,
        "retention_days": o.retention_days,
        "is_demo": o.is_demo,
        "created_at": o.created_at,
    }


@router.get("/organization")
def get_organization(ctx: Ctx = Depends(viewer)):
    return _org(ctx.db.get(Organization, ctx.org_id))


@router.patch("/organization")
def patch_organization(body: OrgPatch, ctx: Ctx = Depends(owner)):
    org = ctx.db.get(Organization, ctx.org_id)
    values = body.model_dump(exclude_unset=True, exclude_none=True)
    if "slug" in values and values["slug"] != org.slug and ctx.db.scalar(select(Organization.id).where(Organization.slug == values["slug"])):
        raise HTTPException(status_code=409, detail="That slug is already taken")
    changes = audit.diff(org, values)
    for k, v in values.items():
        setattr(org, k, v)
    audit.record(ctx.db, ctx.org_id, "organization.updated", actor=ctx.user, object_type="organization", object_id=org.id, metadata=changes)
    ctx.db.commit()
    return _org(org)


def _member(m: Membership, u: User) -> dict:
    return {"user_id": u.id, "email": u.email, "display_name": u.display_name, "role": m.role, "status": m.status, "account_status": u.status, "joined_at": m.created_at}


@router.get("/members")
def list_members(ctx: Ctx = Depends(viewer)):
    rows = ctx.db.execute(
        select(Membership, User).join(User, User.id == Membership.user_id).where(Membership.organization_id == ctx.org_id).order_by(User.email)
    ).all()
    return {"items": [_member(m, u) for m, u in rows]}


def _owner_count(db: Session, org_id: uuid.UUID) -> int:
    return len(db.scalars(select(Membership.id).where(Membership.organization_id == org_id, Membership.role == "owner", Membership.status == "active")).all())


@router.post("/members", status_code=201)
def add_member(body: MemberIn, ctx: Ctx = Depends(owner)):
    """Administrator-provisioned accounts. An existing account is attached without touching its password."""
    email = body.email.lower()
    user = ctx.db.scalar(select(User).where(User.email == email))
    if user is None:
        if not body.password:
            raise HTTPException(status_code=422, detail="A password is required to create a new account")
        user = User(email=email, password_hash=hash_password(body.password), display_name=body.display_name)
        ctx.db.add(user)
        ctx.db.flush()
    existing = ctx.db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.organization_id == ctx.org_id)) if user.id else None
    if existing is not None and existing.status == "active":
        raise HTTPException(status_code=409, detail="User is already a member")
    if existing is not None:  # a revoked member is re-admitted on the same row, keeping the history
        existing.status, existing.role = "active", body.role
        m = existing
    else:
        m = Membership(user_id=user.id, organization_id=ctx.org_id, role=body.role)
        ctx.db.add(m)
    audit.record(ctx.db, ctx.org_id, "member.added", actor=ctx.user, object_type="user", object_id=user.id, metadata={"email": email, "role": body.role})
    ctx.db.commit()
    return _member(m, user)


@router.patch("/members/{user_id}")
def change_role(user_id: uuid.UUID, body: MemberPatch, ctx: Ctx = Depends(owner)):
    m = ctx.db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.organization_id == ctx.org_id, Membership.status == "active"))
    if m is None:
        raise HTTPException(status_code=404, detail="Member not found")
    if m.role == "owner" and body.role != "owner" and _owner_count(ctx.db, ctx.org_id) <= 1:
        raise HTTPException(status_code=409, detail="An organization needs at least one owner")
    old = m.role
    m.role = body.role
    ctx.db.execute(update(AuthSession).where(AuthSession.user_id == user_id, AuthSession.organization_id == ctx.org_id, AuthSession.revoked_at.is_(None)).values(revoked_at=utcnow()))  # privilege change forces re-authentication
    audit.record(ctx.db, ctx.org_id, "member.role_changed", actor=ctx.user, object_type="user", object_id=user_id, metadata={"from": old, "to": body.role})
    ctx.db.commit()
    return _member(m, ctx.db.get(User, user_id))


class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)


@router.post("/organizations", status_code=201)
def create_organization(body: OrgCreate, ctx: Ctx = Depends(viewer)):
    """Any signed-in user may create an additional workspace; they become its owner."""
    import re
    import secrets

    from ..deps import bind_org

    base = re.sub(r"[^a-z0-9]+", "-", body.name.lower()).strip("-")[:60] or "org"
    slug = base
    while ctx.db.scalar(select(Organization.id).where(Organization.slug == slug)):
        slug = f"{base}-{secrets.token_hex(3)}"
    org = Organization(name=body.name.strip(), slug=slug)
    ctx.db.add(org)
    ctx.db.flush()
    ctx.db.add(Membership(user_id=ctx.user.id, organization_id=org.id, role="owner"))
    bind_org(ctx.db, org.id)
    audit.record(ctx.db, org.id, "organization.created", actor=ctx.user, object_type="organization", object_id=org.id)
    ctx.db.commit()
    return _org(org)


@router.delete("/members/{user_id}", status_code=204)
def remove_member(user_id: uuid.UUID, ctx: Ctx = Depends(owner)):
    m = ctx.db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.organization_id == ctx.org_id, Membership.status == "active"))
    if m is None:
        raise HTTPException(status_code=404, detail="Member not found")
    if m.role == "owner" and _owner_count(ctx.db, ctx.org_id) <= 1:
        raise HTTPException(status_code=409, detail="An organization needs at least one owner")
    m.status = "revoked"  # the row is kept so membership history stays reconstructable
    # Sessions pointing at this org for that user are revoked immediately.
    ctx.db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.organization_id == ctx.org_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    audit.record(ctx.db, ctx.org_id, "member.revoked", actor=ctx.user, object_type="user", object_id=user_id)
    ctx.db.commit()


@router.get("/audit-events")
def list_audit_events(
    event_type: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    ctx: Ctx = Depends(analyst),
):
    stmt = select(AuditEvent).where(AuditEvent.organization_id == ctx.org_id)
    if not ctx.can("owner"):  # analysts see investigation and inventory activity, not account or membership administration
        stmt = stmt.where(~AuditEvent.event_type.like("auth.%"), ~AuditEvent.event_type.like("member.%"), ~AuditEvent.event_type.like("organization.%"))
    if event_type:
        stmt = stmt.where(AuditEvent.event_type.like(event_type.replace("%", "") + "%"))
    if object_type:
        stmt = stmt.where(AuditEvent.object_type == object_type)
    if object_id:
        stmt = stmt.where(AuditEvent.object_id == object_id)
    stmt = stmt.order_by(AuditEvent.occurred_at.desc())
    return paginate(
        ctx.db,
        stmt,
        limit,
        offset,
        lambda e: {
            "id": e.id,
            "event_type": e.event_type,
            "actor_id": e.actor_id,
            "actor": e.actor_label,
            "object_type": e.object_type,
            "object_id": e.object_id,
            "occurred_at": e.occurred_at,
            "metadata": e.event_metadata,
        },
    )


@router.get("/change-history")
def change_history(object_type: str | None = None, object_id: uuid.UUID | None = None, limit: int = 50, offset: int = 0, ctx: Ctx = Depends(viewer)):
    stmt = select(ChangeEvent).where(ChangeEvent.organization_id == ctx.org_id)
    if object_type:
        stmt = stmt.where(ChangeEvent.object_type == object_type)
    if object_id:
        stmt = stmt.where(ChangeEvent.object_id == object_id)
    stmt = stmt.order_by(ChangeEvent.occurred_at.desc())
    return paginate(
        ctx.db,
        stmt,
        limit,
        offset,
        lambda c: {"id": c.id, "object_type": c.object_type, "object_id": c.object_id, "action": c.action, "actor_id": c.actor_id, "changes": c.changes, "occurred_at": c.occurred_at},
    )
