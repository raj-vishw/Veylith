import hashlib
import uuid
from datetime import date, datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from ..common import get_owned, paginate
from ..deps import Ctx, analyst, owner, viewer
from ..models import (
    Advisory,
    Asset,
    Case,
    CaseAssessment,
    CaseEvent,
    CaseNote,
    Client,
    Evidence,
    ImpactAssessment,
    Membership,
    Task,
    User,
    utcnow,
)
from ..services import audit
from ..services.storage import read_upload, storage

router = APIRouter(tags=["cases"])

PRIORITY = "^(low|medium|high|critical)$"
# Valid lifecycle moves, enforced in the backend.
TRANSITIONS = {
    "new": {"triage", "closed"},
    "triage": {"investigating", "closed"},
    "investigating": {"evidence_collection", "remediation", "resolved", "triage", "closed"},
    "evidence_collection": {"investigating", "remediation", "closed"},
    "remediation": {"evidence_collection", "investigating", "resolved", "closed"},
    "resolved": {"closed", "investigating"},  # new evidence can reopen a resolved case
    "closed": {"triage"},  # reopen
}
SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY = "^(low|medium|high|critical)$"
CLOSURE_REASONS = ("resolved", "false_positive", "accepted_risk", "duplicate")
OPEN_TASK = ("open", "in_progress", "blocked")


def _member_ids(ctx: Ctx) -> set[uuid.UUID]:
    return set(ctx.db.scalars(select(Membership.user_id).where(Membership.organization_id == ctx.org_id)))


def _check_assignee(ctx: Ctx, assignee_id):
    if assignee_id and assignee_id not in _member_ids(ctx):
        raise HTTPException(status_code=422, detail="Assignee must be a member of this organization")


def event(ctx: Ctx, case: Case, kind: str, summary: str, *, system: bool = False, data: dict | None = None):
    ctx.db.add(
        CaseEvent(organization_id=ctx.org_id, case_id=case.id, kind=kind, summary=summary, is_system=system,
                  actor_id=None if system else ctx.user.id, data=audit.scrub(data or {}))
    )


def _case(c: Case, client: Client | None = None, assignee: User | None = None, advisory: Advisory | None = None) -> dict:
    return {
        "id": c.id, "number": c.number, "reference": f"VEY-{c.number:04d}", "title": c.title, "description": c.description,
        "priority": c.priority, "severity": c.severity or None, "status": c.status, "client_id": c.client_id, "client": client.name if client else None,
        "advisory_id": c.advisory_id, "advisory": advisory.advisory_id if advisory else None,
        "assignee_id": c.assignee_id, "assignee": (assignee.display_name or assignee.email) if assignee else None,
        "due_date": c.due_date, "closure_reason": c.closure_reason, "resolution_summary": c.resolution_summary,
        "version": c.version, "created_at": c.created_at, "updated_at": c.updated_at,
    }


def _case_row(ctx: Ctx, c: Case) -> dict:
    out = _case(c, ctx.db.get(Client, c.client_id) if c.client_id else None, ctx.db.get(User, c.assignee_id) if c.assignee_id else None,
                ctx.db.get(Advisory, c.advisory_id) if c.advisory_id else None)
    open_tasks, overdue = ctx.db.execute(
        select(func.count(), func.count().filter(Task.due_date < date.today())).where(Task.case_id == c.id, Task.status.in_(OPEN_TASK))
    ).one()
    out["open_tasks"], out["overdue_tasks"] = open_tasks, overdue
    return out


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=10000)
    assessment_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    client_id: uuid.UUID | None = None
    priority: str | None = Field(default=None, pattern=PRIORITY)
    severity: str | None = Field(default=None, pattern=SEVERITY)
    assignee_id: uuid.UUID | None = None
    due_date: date | None = None


class CasePatch(BaseModel):
    version: int
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=10000)
    priority: str | None = Field(default=None, pattern=PRIORITY)
    severity: str | None = Field(default=None, pattern=SEVERITY)
    assignee_id: uuid.UUID | None = None
    due_date: date | None = None
    unassign: bool = False


class TransitionIn(BaseModel):
    to: str = Field(pattern="^(new|triage|investigating|evidence_collection|remediation|resolved|closed)$")
    version: int
    note: str = Field(default="", max_length=5000)
    closure_reason: str | None = Field(default=None, pattern="^(resolved|false_positive|accepted_risk|duplicate)$")
    resolution_summary: str = Field(default="", max_length=10000)


@router.get("/cases")
def list_cases(
    status: str | None = None, priority: str | None = None, assignee_id: uuid.UUID | None = None, client_id: uuid.UUID | None = None,
    overdue: bool = False, q: str | None = None, severity: str | None = None, sort: str = "created_at", direction: str = "desc",
    limit: int = 50, offset: int = 0, ctx: Ctx = Depends(viewer),
):
    stmt = select(Case).where(Case.organization_id == ctx.org_id)
    if status:
        stmt = stmt.where(Case.status == status)
    if priority:
        stmt = stmt.where(Case.priority == priority)
    if assignee_id:
        stmt = stmt.where(Case.assignee_id == assignee_id)
    if client_id:
        stmt = stmt.where(Case.client_id == client_id)
    if overdue:
        stmt = stmt.where(Case.due_date < date.today(), Case.status.notin_(("resolved", "closed")))
    if severity:
        stmt = stmt.where(Case.severity == severity)
    if q:
        term = q.strip()
        number = term.upper().removeprefix("VEY-")
        like = Case.title.ilike("%" + term.replace("%", "").replace("_", "") + "%")
        stmt = stmt.where(like | (Case.number == int(number))) if number.isdigit() else stmt.where(like)
    sort_cols = {"created_at": Case.created_at, "updated_at": Case.updated_at, "number": Case.number, "due_date": Case.due_date, "priority": Case.priority, "severity": Case.severity}
    if sort not in sort_cols or direction not in ("asc", "desc"):
        raise HTTPException(status_code=422, detail="Unsupported sort")
    col = sort_cols[sort]
    ordering = (col.asc() if direction == "asc" else col.desc()).nulls_last()
    return paginate(ctx.db, stmt.order_by(ordering, Case.number.desc()), limit, offset, lambda c: _case_row(ctx, c))


@router.post("/cases", status_code=201)
def create_case(body: CaseIn, ctx: Ctx = Depends(analyst)):
    assessments = [get_owned(ctx, ImpactAssessment, aid) for aid in dict.fromkeys(body.assessment_ids)]
    client_id = body.client_id
    if client_id:
        get_owned(ctx, Client, client_id)
    elif assessments:
        client_id = next((a.client_id for a in assessments if a.client_id), None)
    _check_assignee(ctx, body.assignee_id)
    priority = body.priority or (max((a.priority for a in assessments), key=["low", "medium", "high", "critical"].index, default="medium"))
    # Serialise number allocation per organization.
    ctx.db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"case-number:{ctx.org_id}"})
    number = (ctx.db.scalar(select(func.max(Case.number)).where(Case.organization_id == ctx.org_id)) or 0) + 1
    severity = body.severity or _advisory_severity(ctx, assessments)
    case = Case(
        organization_id=ctx.org_id, number=number, severity=severity, client_id=client_id, advisory_id=assessments[0].advisory_id if assessments else None,
        title=body.title, description=body.description, priority=priority, assignee_id=body.assignee_id, due_date=body.due_date, created_by=ctx.user.id,
    )
    ctx.db.add(case)
    ctx.db.flush()
    for a in assessments:
        ctx.db.add(CaseAssessment(organization_id=ctx.org_id, case_id=case.id, assessment_id=a.id))
    event(ctx, case, "case_created", f"Case opened from {len(assessments)} assessment(s)." if assessments else "Case opened.", data={"assessments": [str(a.id) for a in assessments]})
    seen_advisories = set()
    for a in assessments:
        # Automated context, kept distinct from analyst actions. External and internal timestamps are both recorded.
        adv = ctx.db.get(Advisory, a.advisory_id)
        if adv is not None and adv.id not in seen_advisories:
            seen_advisories.add(adv.id)
            published = adv.published_at.strftime("%Y-%m-%d") if adv.published_at else "unknown date"
            event(ctx, case, "advisory_context", f"{adv.advisory_id} was published by {adv.source.upper()} on {published} (external event time); Veylith first observed it on {adv.first_seen_at.strftime('%Y-%m-%d %H:%M UTC')}.",
                  system=True, data={"advisory": adv.advisory_id, "external_published_at": adv.published_at.isoformat() if adv.published_at else None, "first_observed_at": adv.first_seen_at.isoformat()})
        event(ctx, case, "assessment_linked", f"Impact assessment created by deterministic matching at {a.created_at.strftime('%Y-%m-%d %H:%M UTC')} ({a.state.replace('_', ' ')}, {a.match_type} match) and linked to this case.",
              system=True, data={"assessment_id": str(a.id), "state": a.state})
    audit.record(ctx.db, ctx.org_id, "case.created", actor=ctx.user, object_type="case", object_id=case.id, metadata={"number": number, "priority": priority})
    ctx.db.commit()
    return _case_row(ctx, case)


def _advisory_severity(ctx: Ctx, assessments) -> str:
    """Highest advisory severity among the linked assessments; blank when the sources do not say."""
    found = [a.severity.lower() for a in (ctx.db.get(Advisory, x.advisory_id) for x in assessments) if a is not None and a.severity]
    return max((f for f in found if f in SEVERITIES), key=SEVERITIES.index, default="")


def _load(ctx: Ctx, case_id: uuid.UUID) -> Case:
    return get_owned(ctx, Case, case_id)


@router.get("/cases/{case_id}")
def get_case(case_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    c = _load(ctx, case_id)
    out = _case_row(ctx, c)
    out["assessment_ids"] = list(ctx.db.scalars(select(CaseAssessment.assessment_id).where(CaseAssessment.case_id == c.id)))
    out["open_tasks"] = ctx.db.scalar(select(func.count()).select_from(Task).where(Task.case_id == c.id, Task.status.in_(OPEN_TASK))) or 0
    out["allowed_transitions"] = sorted(TRANSITIONS.get(c.status, set()))
    return out


class LinkAssessmentsIn(BaseModel):
    assessment_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)


@router.post("/cases/{case_id}/assessments")
def link_assessments(case_id: uuid.UUID, body: LinkAssessmentsIn, ctx: Ctx = Depends(analyst)):
    c = _load(ctx, case_id)
    if c.status == "closed":
        raise HTTPException(status_code=409, detail="Reopen the case before linking assessments")
    existing = set(ctx.db.scalars(select(CaseAssessment.assessment_id).where(CaseAssessment.case_id == c.id)))
    added = []
    for aid in dict.fromkeys(body.assessment_ids):
        a = get_owned(ctx, ImpactAssessment, aid)  # 404 for another tenant's assessment
        if a.id in existing:
            continue
        ctx.db.add(CaseAssessment(organization_id=ctx.org_id, case_id=c.id, assessment_id=a.id))
        event(ctx, c, "assessment_linked", f"Assessment linked by an analyst ({a.state.replace('_', ' ')}, {a.match_type} match).", data={"assessment_id": str(a.id), "state": a.state})
        added.append(str(a.id))
    if added:
        audit.record(ctx.db, ctx.org_id, "case.assessments_linked", actor=ctx.user, object_type="case", object_id=c.id, metadata={"assessment_ids": added})
    ctx.db.commit()
    return {"linked": added, "assessment_ids": list(ctx.db.scalars(select(CaseAssessment.assessment_id).where(CaseAssessment.case_id == c.id)))}


@router.patch("/cases/{case_id}")
def patch_case(case_id: uuid.UUID, body: CasePatch, ctx: Ctx = Depends(analyst)):
    c = _load(ctx, case_id)
    if body.version != c.version:
        raise HTTPException(status_code=409, detail="This case was changed by someone else. Reload and try again.")
    values = body.model_dump(exclude={"version", "unassign"}, exclude_unset=True, exclude_none=True)
    if body.unassign:
        values["assignee_id"] = None
    if "assignee_id" in values:
        _check_assignee(ctx, values["assignee_id"])
    changes = audit.diff(c, values)
    if not changes:
        return _case_row(ctx, c)
    for k, v in values.items():
        setattr(c, k, v)
    c.version += 1
    for field, ch in changes.items():
        event(ctx, c, f"{field}_changed", f"{field.replace('_', ' ').capitalize()} changed.", data=ch)
    audit.record(ctx.db, ctx.org_id, "case.updated", actor=ctx.user, object_type="case", object_id=c.id, metadata=changes)
    ctx.db.commit()
    return _case_row(ctx, c)


@router.post("/cases/{case_id}/transition")
def transition_case(case_id: uuid.UUID, body: TransitionIn, ctx: Ctx = Depends(analyst)):
    c = _load(ctx, case_id)
    if body.version != c.version:
        raise HTTPException(status_code=409, detail="This case was changed by someone else. Reload and try again.")
    if body.to not in TRANSITIONS.get(c.status, set()):
        raise HTTPException(status_code=409, detail=f"Cannot move a case from '{c.status}' to '{body.to}'")
    if c.status == "closed" and not body.note.strip():
        raise HTTPException(status_code=422, detail="A note is required to reopen a closed case")
    if body.to in ("resolved", "closed"):
        open_tasks = ctx.db.scalar(select(func.count()).select_from(Task).where(Task.case_id == c.id, Task.status.in_(OPEN_TASK))) or 0
        if open_tasks and not (body.to == "closed" and body.closure_reason in ("false_positive", "duplicate")):
            raise HTTPException(status_code=409, detail=f"{open_tasks} remediation task(s) are still open")
        if not body.resolution_summary.strip():
            raise HTTPException(status_code=422, detail="A resolution summary is required")
    if body.to == "closed" and not body.closure_reason:
        raise HTTPException(status_code=422, detail="A closure reason is required to close a case")
    previous = c.status
    c.status = body.to
    if body.to in ("resolved", "closed"):
        c.resolution_summary = body.resolution_summary
    if body.to == "closed":
        c.closure_reason = body.closure_reason or ""
    if previous == "closed":
        c.closure_reason = ""
    c.version += 1
    event(ctx, c, "status_changed", f"Status changed from {previous} to {body.to}." + (f" Note: {body.note}" if body.note else ""),
          data={"from": previous, "to": body.to, "closure_reason": c.closure_reason})
    audit.record(ctx.db, ctx.org_id, "case.status_changed", actor=ctx.user, object_type="case", object_id=c.id,
                 metadata={"previous_status": previous, "new_status": body.to, "closure_reason": c.closure_reason})
    ctx.db.commit()
    return _case_row(ctx, c)


@router.get("/cases/{case_id}/timeline")
def timeline(case_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    c = _load(ctx, case_id)
    emails = dict(ctx.db.execute(select(User.id, User.email).join(Membership, Membership.user_id == User.id).where(Membership.organization_id == ctx.org_id)).all())
    rows = ctx.db.scalars(select(CaseEvent).where(CaseEvent.case_id == c.id).order_by(CaseEvent.occurred_at))
    return {
        "items": [
            {"id": e.id, "kind": e.kind, "summary": e.summary, "is_system": e.is_system, "actor": emails.get(e.actor_id) if e.actor_id else "system",
             "occurred_at": e.occurred_at, "data": e.data}
            for e in rows
        ]
    }


# --------------------------------------------------------------------------- notes
class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=20000)
    visibility: str = Field(default="internal", pattern="^(internal|customer)$")


@router.get("/cases/{case_id}/notes")
def list_notes(case_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    c = _load(ctx, case_id)
    stmt = select(CaseNote).where(CaseNote.case_id == c.id).order_by(CaseNote.created_at)
    if not ctx.can("analyst"):
        stmt = stmt.where(CaseNote.visibility == "customer")  # internal analyst notes stay internal
    return {"items": [{"id": n.id, "body": n.body, "visibility": n.visibility, "author_id": n.author_id, "created_at": n.created_at} for n in ctx.db.scalars(stmt)]}


@router.post("/cases/{case_id}/notes", status_code=201)
def add_note(case_id: uuid.UUID, body: NoteIn, ctx: Ctx = Depends(analyst)):
    c = _load(ctx, case_id)
    n = CaseNote(organization_id=ctx.org_id, case_id=c.id, author_id=ctx.user.id, body=body.body, visibility=body.visibility)
    ctx.db.add(n)
    ctx.db.flush()
    event(ctx, c, "note_added", f"{body.visibility.capitalize()} note added.", data={"note_id": str(n.id), "visibility": body.visibility})
    audit.record(ctx.db, ctx.org_id, "case.note_added", actor=ctx.user, object_type="case", object_id=c.id, metadata={"visibility": body.visibility})
    ctx.db.commit()
    return {"id": n.id, "body": n.body, "visibility": n.visibility, "author_id": n.author_id, "created_at": n.created_at}


# --------------------------------------------------------------------------- tasks
class TaskIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=10000)
    asset_id: uuid.UUID | None = None
    assignee_id: uuid.UUID | None = None
    priority: str = Field(default="medium", pattern=PRIORITY)
    due_date: date | None = None


class TaskPatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=10000)
    assignee_id: uuid.UUID | None = None
    priority: str | None = Field(default=None, pattern=PRIORITY)
    due_date: date | None = None
    status: str | None = Field(default=None, pattern="^(open|in_progress|blocked|done|cancelled)$")
    completion_notes: str | None = Field(default=None, max_length=10000)
    verification_evidence_id: uuid.UUID | None = None


def _task(t: Task) -> dict:
    return {
        "id": t.id, "case_id": t.case_id, "asset_id": t.asset_id, "title": t.title, "description": t.description,
        "assignee_id": t.assignee_id, "priority": t.priority, "due_date": t.due_date, "status": t.status,
        "completion_notes": t.completion_notes, "verification_evidence_id": t.verification_evidence_id,
        "completed_at": t.completed_at, "created_at": t.created_at,
        "verification_status": t.verification_status, "verified_by": t.verified_by, "verified_at": t.verified_at,
        "verification_notes": t.verification_notes, "created_by": t.created_by,
        "overdue": bool(t.due_date and t.due_date < date.today() and t.status in OPEN_TASK),
    }


@router.get("/cases/{case_id}/remediation-tasks")
@router.get("/cases/{case_id}/tasks")
def list_case_tasks(case_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    c = _load(ctx, case_id)
    return {"items": [_task(t) for t in ctx.db.scalars(select(Task).where(Task.case_id == c.id).order_by(Task.created_at))]}


@router.get("/tasks")
def list_tasks(status: str | None = None, assignee_id: uuid.UUID | None = None, overdue: bool = False, limit: int = 50, offset: int = 0, ctx: Ctx = Depends(viewer)):
    stmt = select(Task).where(Task.organization_id == ctx.org_id)
    if status:
        stmt = stmt.where(Task.status == status)
    if assignee_id:
        stmt = stmt.where(Task.assignee_id == assignee_id)
    if overdue:
        stmt = stmt.where(Task.due_date < date.today(), Task.status.in_(OPEN_TASK))
    return paginate(ctx.db, stmt.order_by(Task.due_date.asc().nulls_last(), Task.created_at), limit, offset, _task)


@router.post("/cases/{case_id}/remediation-tasks", status_code=201)
@router.post("/cases/{case_id}/tasks", status_code=201)
def create_task(case_id: uuid.UUID, body: TaskIn, ctx: Ctx = Depends(analyst)):
    c = _load(ctx, case_id)
    if c.status == "closed":
        raise HTTPException(status_code=409, detail="Reopen the case before adding tasks")
    if body.asset_id:
        get_owned(ctx, Asset, body.asset_id)
    _check_assignee(ctx, body.assignee_id)
    t = Task(organization_id=ctx.org_id, case_id=c.id, created_by=ctx.user.id, **body.model_dump())
    ctx.db.add(t)
    ctx.db.flush()
    event(ctx, c, "task_created", f"Task created: {t.title}", data={"task_id": str(t.id)})
    audit.record(ctx.db, ctx.org_id, "task.created", actor=ctx.user, object_type="task", object_id=t.id, metadata={"case_id": str(c.id), "title": t.title})
    ctx.db.commit()
    return _task(t)


@router.get("/remediation-tasks/{task_id}")
@router.get("/tasks/{task_id}")
def get_task(task_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    return _task(get_owned(ctx, Task, task_id))


@router.patch("/remediation-tasks/{task_id}")
@router.patch("/tasks/{task_id}")
def patch_task(task_id: uuid.UUID, body: TaskPatch, ctx: Ctx = Depends(analyst)):
    t = get_owned(ctx, Task, task_id)
    c = _load(ctx, t.case_id)
    values = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None or k in ("assignee_id", "due_date", "verification_evidence_id")}
    if "assignee_id" in values:
        _check_assignee(ctx, values["assignee_id"])
    if values.get("verification_evidence_id"):
        ev = get_owned(ctx, Evidence, values["verification_evidence_id"])
        if ev.case_id != t.case_id:
            raise HTTPException(status_code=422, detail="Evidence belongs to a different case")
    new_status = values.get("status")
    if new_status == "done":
        notes = values.get("completion_notes", t.completion_notes)
        if not (notes or "").strip():
            raise HTTPException(status_code=422, detail="Completion notes are required to complete a task")
    if values.get("verification_evidence_id"):
        ev = get_owned(ctx, Evidence, values["verification_evidence_id"])
        if ev.deleted_at is not None:
            raise HTTPException(status_code=422, detail="Evidence has been deleted")
    changes = audit.diff(t, values)
    for k, v in values.items():
        setattr(t, k, v)
    # Any change to what was claimed invalidates an earlier verification: it checked a different claim.
    if t.verification_status != "unverified" and (("status" in changes and t.status != "done") or "completion_notes" in changes):
        t.verification_status, t.verified_by, t.verified_at, t.verification_notes = "unverified", None, None, ""
        event(ctx, c, "task_verification_reset", f"Verification of '{t.title}' was cleared because the task changed.", system=True, data={"task_id": str(t.id)})
    if new_status == "done" and changes.get("status"):
        t.completed_at = utcnow()
    elif new_status and new_status != "done":
        t.completed_at = None
    if changes:
        if "status" in changes:
            event(ctx, c, "task_status_changed", f"Task '{t.title}' moved to {t.status}.", data={"task_id": str(t.id), **changes["status"]})
        audit.record(ctx.db, ctx.org_id, "task.updated", actor=ctx.user, object_type="task", object_id=t.id, metadata=changes)
    ctx.db.commit()
    return _task(t)


class VerifyTaskIn(BaseModel):
    verification_status: str = Field(pattern="^(verified|rejected)$")
    notes: str = Field(default="", max_length=10000)
    evidence_id: uuid.UUID | None = None


@router.post("/remediation-tasks/{task_id}/verify")
@router.post("/tasks/{task_id}/verify")
def verify_task(task_id: uuid.UUID, body: VerifyTaskIn, ctx: Ctx = Depends(analyst)):
    """Verification is a separate act from completion: someone checks that the fix is in place and records how."""
    t = get_owned(ctx, Task, task_id)
    c = _load(ctx, t.case_id)
    if t.status != "done":
        raise HTTPException(status_code=409, detail="Only a completed task can be verified")
    evidence_id = body.evidence_id or t.verification_evidence_id
    if body.evidence_id:
        ev = get_owned(ctx, Evidence, body.evidence_id)
        if ev.case_id != t.case_id or ev.deleted_at is not None:
            raise HTTPException(status_code=422, detail="Evidence must be an existing item of the same case")
    if body.verification_status == "verified" and not (body.notes.strip() or evidence_id):
        raise HTTPException(status_code=422, detail="Verification needs notes or supporting evidence")
    if body.verification_status == "rejected" and not body.notes.strip():
        raise HTTPException(status_code=422, detail="Explain why the remediation was rejected")
    previous = t.verification_status
    t.verification_status, t.verified_by, t.verified_at, t.verification_notes = body.verification_status, ctx.user.id, utcnow(), body.notes
    if body.evidence_id:
        t.verification_evidence_id = body.evidence_id
    if body.verification_status == "rejected":  # the claim did not hold: the task goes back to work
        t.status, t.completed_at = "in_progress", None
    event(ctx, c, "task_verified", f"Task '{t.title}' {body.verification_status} by an analyst.", data={"task_id": str(t.id), "from": previous, "to": body.verification_status})
    audit.record(ctx.db, ctx.org_id, "task.verified", actor=ctx.user, object_type="task", object_id=t.id,
                 metadata={"case_id": str(c.id), "from": previous, "to": body.verification_status, "evidence_id": str(evidence_id) if evidence_id else None})
    ctx.db.commit()
    return _task(t)


# --------------------------------------------------------------------------- evidence
class EvidenceIn(BaseModel):
    kind: str = Field(pattern="^(url|note)$")
    title: str = Field(min_length=1, max_length=300)
    source_name: str = Field(default="", max_length=200)
    source_url: str = Field(default="", max_length=1000, pattern=r"^(https?://[^\s]+)?$")
    excerpt: str = Field(default="", max_length=20000)
    assessment_id: uuid.UUID | None = None
    collected_at: datetime | None = None


class VerifyIn(BaseModel):
    verification_status: str = Field(pattern="^(unverified|verified|rejected)$")


def _evidence(e: Evidence) -> dict:
    return {
        "id": e.id, "case_id": e.case_id, "assessment_id": e.assessment_id, "kind": e.kind, "title": e.title,
        "source_name": e.source_name, "source_url": e.source_url, "excerpt": e.excerpt, "original_filename": e.original_filename,
        "content_type": e.content_type, "size_bytes": e.size_bytes, "sha256": e.sha256, "verification_status": e.verification_status,
        "reviewed_by": e.reviewed_by, "added_by": e.added_by, "retrieved_at": e.retrieved_at, "collected_at": e.collected_at,
    }


def _check_assessment_in_case(ctx: Ctx, case: Case, assessment_id):
    if assessment_id is None:
        return
    a = get_owned(ctx, ImpactAssessment, assessment_id)
    if ctx.db.scalar(select(CaseAssessment.id).where(CaseAssessment.case_id == case.id, CaseAssessment.assessment_id == a.id)) is None:
        raise HTTPException(status_code=422, detail="Link the assessment to this case before attaching evidence to it")


def _live_evidence(ctx: Ctx, evidence_id: uuid.UUID) -> Evidence:
    e = get_owned(ctx, Evidence, evidence_id)
    if e.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Not found")  # deleted evidence is retained but no longer served
    return e


@router.get("/cases/{case_id}/evidence")
def list_evidence(case_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    c = _load(ctx, case_id)
    return {"items": [_evidence(e) for e in ctx.db.scalars(select(Evidence).where(Evidence.case_id == c.id, Evidence.deleted_at.is_(None)).order_by(Evidence.retrieved_at))]}


@router.post("/cases/{case_id}/evidence", status_code=201)
def add_evidence(case_id: uuid.UUID, body: EvidenceIn, ctx: Ctx = Depends(analyst)):
    c = _load(ctx, case_id)
    _check_assessment_in_case(ctx, c, body.assessment_id)
    if body.kind == "url" and not body.source_url:
        raise HTTPException(status_code=422, detail="source_url is required for URL evidence")
    e = Evidence(organization_id=ctx.org_id, case_id=c.id, added_by=ctx.user.id, **body.model_dump())
    ctx.db.add(e)
    ctx.db.flush()
    event(ctx, c, "evidence_added", f"Evidence added: {e.title}", data={"evidence_id": str(e.id), "kind": e.kind})
    audit.record(ctx.db, ctx.org_id, "evidence.added", actor=ctx.user, object_type="evidence", object_id=e.id, metadata={"case_id": str(c.id), "kind": e.kind})
    ctx.db.commit()
    return _evidence(e)


@router.post("/cases/{case_id}/evidence/files", status_code=201)
async def upload_evidence(
    case_id: uuid.UUID, file: UploadFile = File(...), title: str = Form(default=""), source_name: str = Form(default=""),
    assessment_id: uuid.UUID | None = Form(default=None), collected_at: datetime | None = Form(default=None), ctx: Ctx = Depends(analyst),
):
    c = _load(ctx, case_id)
    _check_assessment_in_case(ctx, c, assessment_id)
    data, content_type, filename = await read_upload(file)
    key, digest = storage().put(ctx.org_id, data)  # random storage name; the client's filename is metadata only
    e = Evidence(
        organization_id=ctx.org_id, case_id=c.id, assessment_id=assessment_id, kind="file", title=(title or filename)[:300],
        source_name=source_name[:200], storage_key=key, original_filename=filename, content_type=content_type,
        size_bytes=len(data), sha256=digest, added_by=ctx.user.id, collected_at=collected_at,
    )
    ctx.db.add(e)
    ctx.db.flush()
    event(ctx, c, "evidence_added", f"File evidence uploaded: {e.title}", data={"evidence_id": str(e.id), "sha256": digest})
    audit.record(ctx.db, ctx.org_id, "evidence.uploaded", actor=ctx.user, object_type="evidence", object_id=e.id,
                 metadata={"case_id": str(c.id), "filename": filename, "sha256": digest, "size": len(data)})
    ctx.db.commit()
    return _evidence(e)


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    return _evidence(_live_evidence(ctx, evidence_id))


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    e = _live_evidence(ctx, evidence_id)
    if e.kind != "file":
        raise HTTPException(status_code=404, detail="Evidence has no file")
    try:
        data = storage().read(ctx.org_id, e.storage_key)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Stored file is missing")
    if hashlib.sha256(data).hexdigest() != e.sha256:  # never hand out a file that no longer matches what was recorded
        audit.record(ctx.db, ctx.org_id, "evidence.integrity_failed", actor=ctx.user, object_type="evidence", object_id=e.id)
        ctx.db.commit()
        raise HTTPException(status_code=409, detail="Stored file no longer matches its recorded SHA-256. Download refused.")
    audit.record(ctx.db, ctx.org_id, "evidence.downloaded", actor=ctx.user, object_type="evidence", object_id=e.id)
    ctx.db.commit()
    safe = "".join(ch for ch in e.original_filename if ch.isalnum() or ch in "._- ") or "evidence"
    return Response(
        content=data, media_type=e.content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe}"', "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"},
    )


@router.get("/evidence/{evidence_id}/integrity")
def check_integrity(evidence_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    """Re-hash the stored object and compare with the digest recorded at upload. Proves unchanged-since-hashing, not authenticity."""
    e = _live_evidence(ctx, evidence_id)
    if e.kind != "file":
        return {"checked": False, "reason": "no file"}
    try:
        actual = hashlib.sha256(storage().read(ctx.org_id, e.storage_key)).hexdigest()
    except FileNotFoundError:
        actual = None
    ok = actual == e.sha256
    audit.record(ctx.db, ctx.org_id, "evidence.integrity_checked", actor=ctx.user, object_type="evidence", object_id=e.id, metadata={"ok": ok})
    ctx.db.commit()
    return {"checked": True, "ok": ok, "recorded_sha256": e.sha256, "actual_sha256": actual, "missing": actual is None}


class DeleteEvidenceIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


@router.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: uuid.UUID, body: DeleteEvidenceIn, ctx: Ctx = Depends(owner)):
    """Retention policy: evidence is soft-deleted (hidden, not served), owners only, reason mandatory. The stored object
    and the audit trail are kept; a retention job, not a request handler, is responsible for any physical purge."""
    e = _live_evidence(ctx, evidence_id)
    in_use = ctx.db.scalar(select(func.count()).select_from(Task).where(Task.verification_evidence_id == e.id, Task.verification_status == "verified")) or 0
    if in_use:
        raise HTTPException(status_code=409, detail="This evidence supports a verified remediation task. Reject or re-verify the task first.")
    e.deleted_at, e.deleted_by, e.deletion_reason = utcnow(), ctx.user.id, body.reason
    c = _load(ctx, e.case_id)
    event(ctx, c, "evidence_deleted", f"Evidence '{e.title}' removed (retained, no longer served). Reason: {body.reason}", data={"evidence_id": str(e.id), "sha256": e.sha256})
    audit.record(ctx.db, ctx.org_id, "evidence.deleted", actor=ctx.user, object_type="evidence", object_id=e.id, metadata={"reason": body.reason, "sha256": e.sha256})
    ctx.db.commit()
    return {"deleted": True}


@router.post("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: uuid.UUID, body: VerifyIn, ctx: Ctx = Depends(analyst)):
    e = _live_evidence(ctx, evidence_id)
    old = e.verification_status
    e.verification_status = body.verification_status
    e.reviewed_by = ctx.user.id
    audit.record(ctx.db, ctx.org_id, "evidence.reviewed", actor=ctx.user, object_type="evidence", object_id=e.id,
                 metadata={"from": old, "to": body.verification_status})
    c = _load(ctx, e.case_id)
    event(ctx, c, "evidence_reviewed", f"Evidence '{e.title}' marked {body.verification_status}.", data={"evidence_id": str(e.id)})
    ctx.db.commit()
    return _evidence(e)
