import re
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import Ctx, _check_origin, bind_org, get_ctx
from ..models import AuthSession, Membership, Organization, User, utcnow
from ..security import (
    enforce_login_limit,
    hash_password,
    needs_rehash,
    new_token,
    session_lifetime,
    token_hash,
    verify_password,
)
from ..services import audit

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=200)
    display_name: str = Field(default="", max_length=200)
    organization_name: str = Field(min_length=2, max_length=200)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=200)
    organization_id: uuid.UUID | None = None


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=200)
    new_password: str = Field(min_length=12, max_length=200)


class SwitchIn(BaseModel):
    organization_id: uuid.UUID


def _slug(db: Session, name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"
    slug = base
    while db.scalar(select(Organization.id).where(Organization.slug == slug)):
        slug = f"{base}-{secrets.token_hex(3)}"
    return slug


def _start_session(db: Session, response: Response, user: User, org_id: uuid.UUID) -> AuthSession:
    s = get_settings()
    token = new_token()
    sess = AuthSession(
        token_hash=token_hash(token),
        user_id=user.id,
        organization_id=org_id,
        csrf_token=new_token(),
        expires_at=utcnow() + session_lifetime(),
    )
    db.add(sess)
    response.set_cookie(
        s.session_cookie_name,
        token,
        max_age=int(session_lifetime().total_seconds()),
        httponly=True,
        secure=s.cookie_secure,
        samesite=s.cookie_samesite,
        path="/",
    )
    return sess


def _me(db: Session, user: User, org_id: uuid.UUID, role: str, sess: AuthSession) -> dict:
    rows = db.execute(
        select(Organization.id, Organization.name, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == user.id, Membership.status == "active", Organization.status == "active")
        .order_by(Organization.name)
    ).all()
    current = next((r for r in rows if r.id == org_id), None)
    return {
        "user": {"id": user.id, "email": user.email, "display_name": user.display_name},
        "organization": {"id": org_id, "name": current.name if current else ""},
        "role": role,
        "organizations": [{"id": r.id, "name": r.name, "role": r.role} for r in rows],
        "csrf_token": sess.csrf_token,
    }


@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, response: Response, db: Session = Depends(get_db)):
    _check_origin(request)
    if not get_settings().allow_registration:
        raise HTTPException(status_code=403, detail="Registration is disabled")
    enforce_login_limit(request, body.email)
    email = body.email.lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Unable to register with these details")
    user = User(email=email, password_hash=hash_password(body.password), display_name=body.display_name)
    org = Organization(name=body.organization_name.strip(), slug=_slug(db, body.organization_name))
    db.add_all([user, org])
    db.flush()
    db.add(Membership(user_id=user.id, organization_id=org.id, role="owner"))
    bind_org(db, org.id)
    audit.record(db, org.id, "auth.registered", actor=user, object_type="user", object_id=user.id)
    sess = _start_session(db, response, user, org.id)
    try:
        db.commit()
    except IntegrityError:  # two simultaneous registrations for the same email
        db.rollback()
        raise HTTPException(status_code=409, detail="Unable to register with these details")
    return _me(db, user, org.id, "owner", sess)


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    _check_origin(request)  # blocks cross-site login (an attacker signing a victim into the attacker's account)
    enforce_login_limit(request, body.email)
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    ok = verify_password(body.password, user.password_hash if user else None)
    if not (ok and user and user.status == "active"):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    q = select(Membership).join(Organization, Organization.id == Membership.organization_id).where(
        Membership.user_id == user.id, Membership.status == "active", Organization.status == "active"
    )
    if body.organization_id:
        q = q.where(Membership.organization_id == body.organization_id)
    membership = db.scalars(q.order_by(Membership.created_at)).first()
    if membership is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    bind_org(db, membership.organization_id)
    audit.record(db, membership.organization_id, "auth.login", actor=user, object_type="user", object_id=user.id)
    sess = _start_session(db, response, user, membership.organization_id)
    db.commit()
    return _me(db, user, membership.organization_id, membership.role, sess)


@router.post("/logout", status_code=204)
def logout(response: Response, ctx: Ctx = Depends(get_ctx)):
    ctx.session.revoked_at = utcnow()
    audit.record(ctx.db, ctx.org_id, "auth.logout", actor=ctx.user, object_type="user", object_id=ctx.user.id)
    ctx.db.commit()
    response.delete_cookie(get_settings().session_cookie_name, path="/")


@router.post("/logout-all", status_code=204)
def logout_all(response: Response, ctx: Ctx = Depends(get_ctx)):
    """Revokes every session for the current user (e.g. after a suspected compromise)."""
    ctx.db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == ctx.user.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    audit.record(ctx.db, ctx.org_id, "auth.logout_all", actor=ctx.user, object_type="user", object_id=ctx.user.id)
    ctx.db.commit()
    response.delete_cookie(get_settings().session_cookie_name, path="/")


@router.get("/me")
def me(ctx: Ctx = Depends(get_ctx)):
    return _me(ctx.db, ctx.user, ctx.org_id, ctx.role, ctx.session)


@router.get("/csrf")
def csrf(ctx: Ctx = Depends(get_ctx)):
    return {"csrf_token": ctx.session.csrf_token}


@router.post("/switch-org")
def switch_org(body: SwitchIn, ctx: Ctx = Depends(get_ctx)):
    membership = ctx.db.scalar(
        select(Membership).where(Membership.user_id == ctx.user.id, Membership.organization_id == body.organization_id, Membership.status == "active")
    )
    if membership is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    ctx.session.organization_id = membership.organization_id
    bind_org(ctx.db, membership.organization_id)
    audit.record(ctx.db, membership.organization_id, "auth.switch_org", actor=ctx.user, object_type="user", object_id=ctx.user.id)
    ctx.db.commit()
    return _me(ctx.db, ctx.user, membership.organization_id, membership.role, ctx.session)


@router.post("/change-password", status_code=204)
def change_password(body: PasswordIn, request: Request, ctx: Ctx = Depends(get_ctx)):
    enforce_login_limit(request, ctx.user.email)  # shares the login throttle: this is also a password oracle
    if not verify_password(body.current_password, ctx.user.password_hash):
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    if body.current_password == body.new_password:
        raise HTTPException(status_code=422, detail="Choose a different password")
    ctx.user.password_hash = hash_password(body.new_password)
    # Every other session of this user is signed out; the current one stays.
    ctx.db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == ctx.user.id, AuthSession.id != ctx.session.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    audit.record(ctx.db, ctx.org_id, "auth.password_changed", actor=ctx.user, object_type="user", object_id=ctx.user.id)
    ctx.db.commit()
