import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from ..common import get_owned, paginate
from ..config import get_settings
from ..deps import Ctx, analyst, owner, viewer
from ..models import (
    Advisory,
    AdvisoryMatch,
    AdvisoryRevision,
    AffectedProduct,
    AssessmentEvent,
    AssessmentEvidence,
    Asset,
    Case,
    CaseAssessment,
    Client,
    CorrelationRun,
    Evidence,
    ImpactAssessment,
    IngestionRun,
    Membership,
    Product,
    Relationship,
    Vendor,
    utcnow,
)
from ..security import enforce_expensive_limit
from ..services import audit, outbox
from ..services.correlation import derive_state, rescore_exposure

router = APIRouter(tags=["intelligence"])

SEVERITIES = ("unknown", "low", "medium", "high", "critical")


def _advisory(a: Advisory) -> dict:
    return {
        "id": a.id, "advisory_id": a.advisory_id, "source": a.source, "title": a.title, "severity": a.severity,
        "cvss_score": a.cvss_score, "known_exploited": a.known_exploited, "published_at": a.published_at,
        "modified_at": a.modified_at, "source_url": a.source_url, "is_synthetic": a.is_synthetic,
        "first_seen_at": a.first_seen_at, "last_ingested_at": a.last_ingested_at,
    }


@router.get("/advisories")
def list_advisories(
    q: str | None = None, severity: str | None = None, known_exploited: bool | None = None,
    published_after: datetime | None = None, matched_only: bool = False, limit: int = 50, offset: int = 0,
    ctx: Ctx = Depends(viewer),
):
    stmt = select(Advisory)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Advisory.advisory_id.ilike(like), Advisory.title.ilike(like)))
    if severity:
        stmt = stmt.where(Advisory.severity == severity)
    if known_exploited is not None:
        stmt = stmt.where(Advisory.known_exploited == known_exploited)
    if published_after:
        stmt = stmt.where(Advisory.published_at >= published_after)
    if matched_only:
        stmt = stmt.where(Advisory.id.in_(select(ImpactAssessment.advisory_id).where(ImpactAssessment.organization_id == ctx.org_id)))
    return paginate(ctx.db, stmt.order_by(func.coalesce(Advisory.published_at, Advisory.first_seen_at).desc()), limit, offset, _advisory)


@router.get("/advisories/{advisory_id}")
def get_advisory(advisory_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    a = ctx.db.get(Advisory, advisory_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Advisory not found")
    out = _advisory(a)
    out.update(
        description=a.description, mitigation=a.mitigation, references=a.references,
        kev_added_at=a.kev_added_at, kev_due_date=a.kev_due_date,
        affected_products=[
            {"vendor": p.vendor, "product": p.product, "cpe": p.cpe, "version": p.exact_version, "start_including": p.start_including,
             "start_excluding": p.start_excluding, "end_including": p.end_including, "end_excluding": p.end_excluding}
            for p in ctx.db.scalars(select(AffectedProduct).where(AffectedProduct.advisory_id == a.id).limit(200))
        ],
        revisions=[
            {"changed_at": r.changed_at, "changes": r.changes}
            for r in ctx.db.scalars(select(AdvisoryRevision).where(AdvisoryRevision.advisory_id == a.id).order_by(AdvisoryRevision.changed_at.desc()).limit(20))
        ],
        synthetic_notice="Synthetic demonstration data, not real intelligence." if a.is_synthetic else None,
    )
    matches = ctx.db.execute(
        select(AdvisoryMatch, Product, Vendor).join(Product, Product.id == AdvisoryMatch.product_id).join(Vendor, Vendor.id == AdvisoryMatch.vendor_id)
        .where(AdvisoryMatch.organization_id == ctx.org_id, AdvisoryMatch.advisory_id == a.id).order_by(Vendor.name, Product.name)
    ).all()
    out["matching_products"] = [
        {"match_id": m.id, "product_id": p.id, "product": f"{p.name} {p.version}".strip(), "vendor_id": v.id, "vendor": v.name, "status": m.status, "method": m.method, "version_status": m.version_status}
        for m, p, v in matches
    ]
    return out


# --------------------------------------------------------------------------- ingestion runs
class IngestionIn(BaseModel):
    source: str = Field(pattern="^(nvd|kev|fixture)$")


def _run(r: IngestionRun) -> dict:
    return {
        "id": r.id, "source": r.source, "status": r.status, "started_at": r.started_at, "finished_at": r.finished_at,
        "records_seen": r.records_seen, "records_new": r.records_new, "records_updated": r.records_updated,
        "records_rejected": r.records_rejected, "attempts": r.attempts, "catalog_version": r.catalog_version, "error": r.error,
    }


# A source is "stale" when it has not been checked successfully within this window. A skipped run (catalogue unchanged) counts as a successful check.
STALE_AFTER = {"nvd": timedelta(hours=6), "kev": timedelta(hours=48)}


@router.get("/ingestion-runs")
def list_ingestion_runs(limit: int = 20, offset: int = 0, ctx: Ctx = Depends(viewer)):
    return paginate(ctx.db, select(IngestionRun).order_by(IngestionRun.started_at.desc()), limit, offset, _run)


def _source_health(db) -> dict:
    """Per source: latest attempt, last successful check, and an explicit verdict, so that 'no new advisories' is never confused with
    'the source could not be checked'. status: healthy | stale | failing | never_run."""
    now = datetime.now(UTC)
    out = []
    for source in ("nvd", "kev"):
        latest = db.scalar(select(IngestionRun).where(IngestionRun.source == source).order_by(IngestionRun.started_at.desc()))
        ok = db.scalar(select(IngestionRun).where(IngestionRun.source == source, IngestionRun.status.in_(("succeeded", "skipped"))).order_by(IngestionRun.started_at.desc()))
        last_ok = ok.finished_at if ok else None
        if latest is None:
            verdict, message = "never_run", "This source has never been checked, so absence of advisories means nothing yet."
        elif latest.status == "failed":
            verdict, message = "failing", f"The latest attempt failed: {latest.error or 'unknown error'}. Results may be missing advisories."
        elif last_ok is None or now - last_ok > STALE_AFTER[source]:
            verdict, message = "stale", f"No successful check in the last {int(STALE_AFTER[source].total_seconds() // 3600)} hours; data may be out of date."
        else:
            verdict, message = "healthy", "Checked recently."
        out.append({"source": source, "status": verdict, "message": message, "latest": _run(latest) if latest else None, "last_success_at": last_ok,
                    "stale_after_hours": int(STALE_AFTER[source].total_seconds() // 3600)})
    return {"sources": out, "any_problem": any(o["status"] != "healthy" for o in out)}


@router.get("/ingestion-health")
def ingestion_health(ctx: Ctx = Depends(viewer)):
    return _source_health(ctx.db)


@router.post("/ingestion-runs", status_code=202)
def create_ingestion_run(body: IngestionIn, ctx: Ctx = Depends(owner)):
    from ..db import SessionLocal
    from ..services.ingestion import start_run

    if body.source == "fixture" and get_settings().environment == "production":
        raise HTTPException(status_code=403, detail="Synthetic fixtures cannot be loaded in production")
    enforce_expensive_limit("ingestion", ctx.org_id, ctx.user.id)
    with SessionLocal() as db:  # ingestion tables are global, so the run is recorded outside the tenant session
        run = start_run(db, body.source, ctx.user.id)
        run_id, payload = run.id, _run(run)
    audit.record(ctx.db, ctx.org_id, "ingestion.requested", actor=ctx.user, object_type="ingestion_run", object_id=run_id, metadata={"source": body.source})
    outbox.enqueue(ctx.db, "app.workers.tasks.ingest_source", [str(run_id), body.source])
    ctx.db.commit()
    outbox.flush()
    return payload


# --------------------------------------------------------------------------- correlation
@router.post("/correlation-runs", status_code=202)
def create_correlation_run(ctx: Ctx = Depends(analyst)):
    """Re-evaluate this organization's inventory against all advisories (e.g. after inventory changes)."""
    enforce_expensive_limit("correlation", ctx.org_id, ctx.user.id)
    audit.record(ctx.db, ctx.org_id, "correlation.requested", actor=ctx.user)
    outbox.enqueue(ctx.db, "app.workers.tasks.run_correlation", [str(ctx.org_id), str(ctx.user.id)])
    ctx.db.commit()
    outbox.flush()
    return {"status": "queued"}


@router.get("/correlation-runs")
def list_correlation_runs(limit: int = 20, offset: int = 0, ctx: Ctx = Depends(viewer)):
    stmt = select(CorrelationRun).where(CorrelationRun.organization_id == ctx.org_id).order_by(CorrelationRun.started_at.desc())
    return paginate(
        ctx.db, stmt, limit, offset,
        lambda r: {"id": r.id, "status": r.status, "started_at": r.started_at, "finished_at": r.finished_at,
                   "advisories_considered": r.advisories_considered, "assessments_created": r.assessments_created,
                   "assessments_updated": r.assessments_updated, "error": r.error},
    )


# --------------------------------------------------------------------------- assessments
STATE_PATTERN = "^(potential_impact|insufficient_data|confirmed_dependency|exposure_verified|compromise_confirmed|no_match_found)$"


class ReviewIn(BaseModel):
    review_status: str = Field(pattern="^(reviewed|dismissed|unreviewed)$")
    state: str | None = Field(default=None, pattern=STATE_PATTERN)  # convenience: maps onto the separate fields below
    exposure_status: str | None = Field(default=None, pattern="^(unverified|verified|not_applicable)$")
    compromise_status: str | None = Field(default=None, pattern="^(unknown|suspected|confirmed|not_confirmed)$")
    remediation_status: str | None = Field(default=None, pattern="^(not_started|in_progress|completed|verified)$")
    dependency_confirmed: bool | None = None
    assigned_to: uuid.UUID | None = None
    note: str = Field(default="", max_length=5000)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class IncorrectIn(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


def _assessment(a: ImpactAssessment, adv: Advisory | None = None, product: Product | None = None, vendor: Vendor | None = None, client: Client | None = None, detail: bool = False) -> dict:
    out = {
        "id": a.id, "advisory_id": a.advisory_id, "advisory": adv.advisory_id if adv else None, "advisory_title": adv.title if adv else None,
        "severity": adv.severity if adv else None, "known_exploited": adv.known_exploited if adv else None,
        "synthetic": adv.is_synthetic if adv else None,
        "product_id": a.product_id, "product": f"{product.name} {product.version}".strip() if product else None,
        "vendor_id": a.vendor_id, "vendor": vendor.name if vendor else None,
        "client_id": a.client_id, "client": client.name if client else None,
        "state": a.state, "match_type": a.match_type, "version_status": a.version_status, "priority": a.priority,
        "match_id": a.match_id, "match_status": a.match_status, "exposure_status": a.exposure_status, "compromise_status": a.compromise_status,
        "remediation_status": a.remediation_status, "dependency_confirmed": a.dependency_confirmed, "assigned_to": a.assigned_to,
        "matcher_version": a.matcher_version, "last_evaluated_at": a.last_evaluated_at,
        "source_confidence": a.source_confidence, "match_confidence": a.match_confidence,
        "relationship_confidence": a.relationship_confidence, "impact_confidence": a.impact_confidence,
        "review_status": a.review_status, "reviewed_at": a.reviewed_at, "created_at": a.created_at, "updated_at": a.updated_at,
    }
    if detail:
        out.update(priority_factors=a.priority_factors, evidence=a.evidence, unknowns=a.unknowns, recommended_steps=a.recommended_steps, path_relationship_ids=a.path_relationship_ids)
    return out


def _joined(ctx: Ctx):
    return (
        select(ImpactAssessment, Advisory, Product, Vendor, Client)
        .join(Advisory, Advisory.id == ImpactAssessment.advisory_id)
        .join(Product, Product.id == ImpactAssessment.product_id)
        .join(Vendor, Vendor.id == ImpactAssessment.vendor_id)
        .outerjoin(Client, Client.id == ImpactAssessment.client_id)
        .where(ImpactAssessment.organization_id == ctx.org_id)
    )


_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@router.get("/assessments")
def list_assessments(
    state: str | None = None, review_status: str | None = None, priority: str | None = None, severity: str | None = None,
    client_id: uuid.UUID | None = None, vendor_id: uuid.UUID | None = None, advisory_id: uuid.UUID | None = None,
    published_after: datetime | None = None, include_no_match: bool = False, known_exploited: bool | None = None,
    match_status: str | None = None, remediation_status: str | None = None, asset_criticality: str | None = None, assigned_to: uuid.UUID | None = None,
    limit: int = 50, offset: int = 0,
    ctx: Ctx = Depends(viewer),
):
    stmt = _joined(ctx)
    if known_exploited is not None:
        stmt = stmt.where(Advisory.known_exploited == known_exploited)
    if match_status:
        stmt = stmt.where(ImpactAssessment.match_status == match_status)
    if remediation_status:
        stmt = stmt.where(ImpactAssessment.remediation_status == remediation_status)
    if assigned_to:
        stmt = stmt.where(ImpactAssessment.assigned_to == assigned_to)
    if asset_criticality:
        stmt = stmt.where(ImpactAssessment.evidence["assets"].contains([{"criticality": asset_criticality}]))
    if state:
        stmt = stmt.where(ImpactAssessment.state == state)
    elif not include_no_match:
        stmt = stmt.where(ImpactAssessment.state != "no_match_found")
    if review_status:
        stmt = stmt.where(ImpactAssessment.review_status == review_status)
    if priority:
        stmt = stmt.where(ImpactAssessment.priority == priority)
    if severity:
        stmt = stmt.where(Advisory.severity == severity)
    if client_id:
        stmt = stmt.where(ImpactAssessment.client_id == client_id)
    if vendor_id:
        stmt = stmt.where(ImpactAssessment.vendor_id == vendor_id)
    if advisory_id:
        stmt = stmt.where(ImpactAssessment.advisory_id == advisory_id)
    if published_after:
        stmt = stmt.where(Advisory.published_at >= published_after)
    total = ctx.db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    from sqlalchemy import case as sql_case

    order = sql_case(_PRIORITY_ORDER, value=ImpactAssessment.priority, else_=4)
    rows = ctx.db.execute(stmt.order_by(order, ImpactAssessment.updated_at.desc()).limit(max(1, min(limit, 100))).offset(max(0, offset))).all()
    return {"items": [_assessment(*r) for r in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    get_owned(ctx, ImpactAssessment, assessment_id)
    row = ctx.db.execute(_joined(ctx).where(ImpactAssessment.id == assessment_id)).first()
    out = _assessment(*row, detail=True)
    out["events"] = [
        {"event_type": e.event_type, "from_state": e.from_state, "to_state": e.to_state, "actor_id": e.actor_id, "note": e.note, "occurred_at": e.occurred_at}
        for e in ctx.db.scalars(select(AssessmentEvent).where(AssessmentEvent.assessment_id == assessment_id).order_by(AssessmentEvent.occurred_at))
    ]
    out["case_ids"] = [c for c in ctx.db.scalars(select(CaseAssessment.case_id).where(CaseAssessment.assessment_id == assessment_id))]
    out["synthetic_notice"] = "Based on synthetic demonstration data." if row[1].is_synthetic else None
    out["evidence_items"] = [
        {"id": e.id, "kind": e.kind, "ref_id": e.ref_id, "summary": e.summary, "snapshot": e.snapshot, "created_at": e.created_at, "superseded_at": e.superseded_at}
        for e in ctx.db.scalars(select(AssessmentEvidence).where(AssessmentEvidence.assessment_id == assessment_id).order_by(AssessmentEvidence.created_at))
    ]
    m = ctx.db.get(AdvisoryMatch, out["match_id"]) if out["match_id"] else None
    out["match"] = _match(m) if m else None
    return out


def _apply_state(a: ImpactAssessment, state: str) -> None:
    """Translate the legacy single-state vocabulary onto the separate status fields."""
    if state == "confirmed_dependency":
        a.dependency_confirmed = True
    elif state == "exposure_verified":
        a.dependency_confirmed, a.exposure_status = True, "verified"
    elif state == "compromise_confirmed":
        a.dependency_confirmed, a.compromise_status = True, "confirmed"
    elif state in ("potential_impact", "insufficient_data"):
        a.dependency_confirmed, a.exposure_status, a.compromise_status = False, "unverified", "unknown"
    elif state == "no_match_found":
        a.match_status = "no_match"


@router.post("/assessments/{assessment_id}/review")
def review_assessment(assessment_id: uuid.UUID, body: ReviewIn, ctx: Ctx = Depends(analyst)):
    a = get_owned(ctx, ImpactAssessment, assessment_id)
    before = (a.state, a.exposure_status, a.compromise_status, a.dependency_confirmed)
    if body.state and body.state != a.state:
        _apply_state(a, body.state)
    for field in ("exposure_status", "compromise_status", "remediation_status", "dependency_confirmed"):
        value = getattr(body, field)
        if value is not None:
            setattr(a, field, value)
    if body.assigned_to is not None:
        if not ctx.db.scalar(select(Membership.id).where(Membership.user_id == body.assigned_to, Membership.organization_id == ctx.org_id, Membership.status == "active")):
            raise HTTPException(status_code=422, detail="Assignee must be an active member of this organization")
        a.assigned_to = body.assigned_to
    decision_changed = before[1:] != (a.exposure_status, a.compromise_status, a.dependency_confirmed)
    if decision_changed and not body.note.strip():
        ctx.db.rollback()
        raise HTTPException(status_code=422, detail="A note explaining the decision is required when changing the exposure, compromise or dependency status")
    if a.compromise_status == "confirmed" and before[2] != "confirmed":
        has_evidence = ctx.db.scalar(
            select(func.count()).select_from(Evidence).where(Evidence.organization_id == ctx.org_id, Evidence.assessment_id == a.id, Evidence.verification_status == "verified")
        )
        if not has_evidence:
            ctx.db.rollback()
            raise HTTPException(status_code=422, detail="Confirming compromise requires verified evidence attached to this assessment")
    a.state = derive_state(a)
    if a.exposure_status != before[1]:
        a.priority_factors, a.priority = rescore_exposure(a.priority_factors, a.exposure_status)
    a.review_status = body.review_status
    a.reviewed_by = ctx.user.id
    a.reviewed_at = utcnow()
    ctx.db.add(AssessmentEvent(organization_id=ctx.org_id, assessment_id=a.id, event_type="reviewed", from_state=before[0], to_state=a.state, actor_id=ctx.user.id, note=body.note))
    if body.note.strip():
        ctx.db.add(AssessmentEvidence(organization_id=ctx.org_id, assessment_id=a.id, kind="analyst_note", ref_id=str(ctx.user.id), summary=body.note[:500], snapshot={"by": ctx.user.email, "decision": {"exposure": a.exposure_status, "compromise": a.compromise_status, "review": body.review_status}}))
    audit.record(ctx.db, ctx.org_id, "assessment.reviewed", actor=ctx.user, object_type="assessment", object_id=a.id,
                 metadata={"review_status": body.review_status, "from_state": before[0], "to_state": a.state, "exposure": a.exposure_status, "compromise": a.compromise_status})
    ctx.db.commit()
    return get_assessment(assessment_id, ctx)


@router.post("/assessments/{assessment_id}/notes", status_code=201)
def add_assessment_note(assessment_id: uuid.UUID, body: NoteIn, ctx: Ctx = Depends(analyst)):
    """An analyst note is stored as an event and as preserved evidence; it never alters the source advisory or the match."""
    a = get_owned(ctx, ImpactAssessment, assessment_id)
    ctx.db.add(AssessmentEvent(organization_id=ctx.org_id, assessment_id=a.id, event_type="note", from_state=a.state, to_state=a.state, actor_id=ctx.user.id, note=body.body))
    ctx.db.add(AssessmentEvidence(organization_id=ctx.org_id, assessment_id=a.id, kind="analyst_note", ref_id=str(ctx.user.id), summary=body.body[:500], snapshot={"by": ctx.user.email}))
    audit.record(ctx.db, ctx.org_id, "assessment.note_added", actor=ctx.user, object_type="assessment", object_id=a.id)
    ctx.db.commit()
    return {"status": "added"}


@router.post("/assessments/{assessment_id}/re-evaluate", status_code=202)
def request_re_evaluation(assessment_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    """Queue a fresh correlation for this organization (through the outbox, so it is not lost if Redis is down)."""
    a = get_owned(ctx, ImpactAssessment, assessment_id)
    enforce_expensive_limit("correlation", ctx.org_id, ctx.user.id)
    ctx.db.add(AssessmentEvent(organization_id=ctx.org_id, assessment_id=a.id, event_type="re_evaluation_requested", from_state=a.state, to_state=a.state, actor_id=ctx.user.id, note="Analyst requested re-evaluation."))
    audit.record(ctx.db, ctx.org_id, "assessment.re_evaluation_requested", actor=ctx.user, object_type="assessment", object_id=a.id)
    outbox.enqueue(ctx.db, "app.workers.tasks.run_correlation", [str(ctx.org_id), str(ctx.user.id)], dedupe_key=f"correlate:{ctx.org_id}")
    ctx.db.commit()
    outbox.flush()
    return {"status": "queued"}


# --------------------------------------------------------------------------- advisory matches
def _match(m: AdvisoryMatch) -> dict:
    return {
        "id": m.id, "advisory_id": m.advisory_id, "product_id": m.product_id, "vendor_id": m.vendor_id, "method": m.method, "status": m.status,
        "version_status": m.version_status, "observed_version": m.observed_version, "affected_range": m.affected_range, "matcher_version": m.matcher_version,
        "evidence": m.evidence, "incorrect_reason": m.incorrect_reason, "marked_by": m.marked_by, "matched_at": m.matched_at, "updated_at": m.updated_at,
    }


@router.get("/matches")
def list_matches(advisory_id: uuid.UUID | None = None, product_id: uuid.UUID | None = None, status: str | None = None, limit: int = 50, offset: int = 0, ctx: Ctx = Depends(viewer)):
    stmt = select(AdvisoryMatch).where(AdvisoryMatch.organization_id == ctx.org_id)
    if advisory_id:
        stmt = stmt.where(AdvisoryMatch.advisory_id == advisory_id)
    if product_id:
        stmt = stmt.where(AdvisoryMatch.product_id == product_id)
    if status:
        stmt = stmt.where(AdvisoryMatch.status == status)
    return paginate(ctx.db, stmt.order_by(AdvisoryMatch.matched_at.desc()), limit, offset, _match)


@router.get("/matches/{match_id}")
def get_match(match_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    return _match(get_owned(ctx, AdvisoryMatch, match_id))


@router.post("/matches/{match_id}/incorrect")
def mark_match_incorrect(match_id: uuid.UUID, body: IncorrectIn, ctx: Ctx = Depends(analyst)):
    """An analyst declares a match wrong. The match and its original evidence are kept (never deleted or rewritten);
    linked assessments are dismissed, and later correlation runs will not resurrect the match."""
    m = get_owned(ctx, AdvisoryMatch, match_id)
    m.status, m.incorrect_reason, m.marked_by = "incorrect", body.reason, ctx.user.id
    for a in ctx.db.scalars(select(ImpactAssessment).where(ImpactAssessment.match_id == m.id)):
        before = a.state
        a.match_status, a.review_status, a.reviewed_by, a.reviewed_at = "no_match", "dismissed", ctx.user.id, utcnow()
        a.state = derive_state(a)
        ctx.db.add(AssessmentEvent(organization_id=ctx.org_id, assessment_id=a.id, event_type="match_marked_incorrect", from_state=before, to_state=a.state, actor_id=ctx.user.id, note=body.reason))
    audit.record(ctx.db, ctx.org_id, "match.marked_incorrect", actor=ctx.user, object_type="match", object_id=m.id, metadata={"reason": body.reason[:200]})
    ctx.db.commit()
    return _match(m)


@router.post("/matches/{match_id}/restore")
def restore_match(match_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    """Undo a mistaken 'incorrect' decision; the next correlation re-evaluates the match from scratch."""
    m = get_owned(ctx, AdvisoryMatch, match_id)
    if m.status != "incorrect":
        raise HTTPException(status_code=409, detail="Only a match marked incorrect can be restored")
    m.status = "needs_review"
    audit.record(ctx.db, ctx.org_id, "match.restored", actor=ctx.user, object_type="match", object_id=m.id)
    outbox.enqueue(ctx.db, "app.workers.tasks.run_correlation", [str(ctx.org_id), str(ctx.user.id)], dedupe_key=f"correlate:{ctx.org_id}")
    ctx.db.commit()
    outbox.flush()
    return _match(m)


@router.get("/dashboard")
def dashboard(ctx: Ctx = Depends(viewer)):
    db, org = ctx.db, ctx.org_id
    active = (ImpactAssessment.organization_id == org, ImpactAssessment.state != "no_match_found")

    def count(*conds):
        return db.scalar(select(func.count()).select_from(ImpactAssessment).where(*conds)) or 0

    new_advisories = db.scalars(select(Advisory).order_by(Advisory.first_seen_at.desc()).limit(8)).all()
    high = db.execute(
        _joined(ctx).where(ImpactAssessment.state != "no_match_found", ImpactAssessment.priority.in_(("critical", "high"))).order_by(ImpactAssessment.updated_at.desc()).limit(8)
    ).all()
    recent = db.execute(_joined(ctx).where(ImpactAssessment.state != "no_match_found").order_by(ImpactAssessment.updated_at.desc()).limit(8)).all()
    affected_clients = db.execute(
        select(Client.id, Client.name, func.count(ImpactAssessment.id))
        .join(ImpactAssessment, ImpactAssessment.client_id == Client.id)
        .where(ImpactAssessment.organization_id == org, ImpactAssessment.state != "no_match_found")
        .group_by(Client.id, Client.name)
        .order_by(func.count(ImpactAssessment.id).desc())
        .limit(10)
    ).all()
    failed_ingest = db.scalars(select(IngestionRun).where(IngestionRun.status == "failed").order_by(IngestionRun.started_at.desc()).limit(5)).all()
    failed_corr = db.scalars(select(CorrelationRun).where(CorrelationRun.organization_id == org, CorrelationRun.status == "failed").order_by(CorrelationRun.started_at.desc()).limit(5)).all()
    case_counts = dict(db.execute(select(Case.status, func.count(Case.id)).where(Case.organization_id == org).group_by(Case.status)).all())
    inventory = {
        "clients": db.scalar(select(func.count()).select_from(Client).where(Client.organization_id == org, Client.archived_at.is_(None))) or 0,
        "vendors": db.scalar(select(func.count()).select_from(Vendor).where(Vendor.organization_id == org, Vendor.deleted_at.is_(None))) or 0,
        "assets": db.scalar(select(func.count()).select_from(Asset).where(Asset.organization_id == org, Asset.deleted_at.is_(None))) or 0,
        "relationships": db.scalar(select(func.count()).select_from(Relationship).where(Relationship.organization_id == org)) or 0,
    }
    assets_seen: dict[str, dict] = {}
    for a in db.scalars(select(ImpactAssessment).where(*active, ImpactAssessment.priority.in_(("critical", "high")))):
        for asset in a.evidence.get("assets", []):
            slot = assets_seen.setdefault(asset["id"], {"asset_id": asset["id"], "name": asset["name"], "criticality": asset["criticality"], "internet_exposed": asset["internet_exposed"], "assessments": 0})
            slot["assessments"] += 1
    high_priority_assets = sorted(assets_seen.values(), key=lambda x: (-x["assessments"], x["name"]))[:10]
    return {
        "inventory": inventory,
        "high_priority_assets": high_priority_assets,
        "sources": _source_health(db),
        "counts": {
            "active_assessments": count(*active),
            "unreviewed": count(*active, ImpactAssessment.review_status == "unreviewed"),
            "high_priority": count(*active, ImpactAssessment.priority.in_(("critical", "high"))),
            "insufficient_data": count(*active, ImpactAssessment.state == "insufficient_data"),
            "potential": count(*active, ImpactAssessment.state.in_(("potential_impact", "insufficient_data"))),
            "confirmed_dependency": count(*active, ImpactAssessment.state == "confirmed_dependency"),
            "exposure_verified": count(*active, ImpactAssessment.exposure_status == "verified"),
            "compromise_confirmed": count(*active, ImpactAssessment.compromise_status == "confirmed"),
            "open_cases": sum(v for k, v in case_counts.items() if k not in ("resolved", "closed")),
        },
        "new_advisories": [_advisory(a) for a in new_advisories],
        "high_priority_assessments": [_assessment(*r) for r in high],
        "recently_changed_assessments": [_assessment(*r) for r in recent],
        "affected_clients": [{"client_id": c, "client": n, "assessments": k} for c, n, k in affected_clients],
        "failed_ingestion_runs": [_run(r) for r in failed_ingest],
        "failed_correlation_runs": [{"id": r.id, "started_at": r.started_at, "error": r.error} for r in failed_corr],
    }
