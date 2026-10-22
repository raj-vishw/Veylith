import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..common import get_owned
from ..deps import Ctx, analyst, viewer
from ..models import Case, CaseEvent, Report, utcnow
from ..security import enforce_expensive_limit
from ..services import audit, outbox
from ..services.reports import ERROR_MESSAGES, STALE_AFTER
from ..services.storage import storage

router = APIRouter(tags=["reports"])


class ReportIn(BaseModel):
    kind: str = Field(default="technical", pattern="^(technical|executive)$")


def _report(r: Report) -> dict:
    stale = r.status == "processing" and r.started_at is not None and utcnow() - r.started_at > STALE_AFTER
    return {
        "id": r.id, "case_id": r.case_id, "kind": r.kind, "status": r.status, "size_bytes": r.size_bytes, "sha256": r.sha256,
        "template_version": r.template_version, "attempts": r.attempts, "retryable": r.status == "failed" or stale,
        # internal exception text is never returned: only a category and a fixed, safe message
        "error_code": r.error_code or None, "error": ERROR_MESSAGES.get(r.error_code, ERROR_MESSAGES["render_failed"]) if r.status == "failed" else "",
        "requested_by": r.requested_by, "created_at": r.created_at, "completed_at": r.completed_at,
    }


@router.post("/cases/{case_id}/reports", status_code=202)
def create_report(case_id: uuid.UUID, body: ReportIn, ctx: Ctx = Depends(analyst)):
    case = get_owned(ctx, Case, case_id)
    # Deduplicate: one live job per case and kind. A second click returns the job already in flight.
    live = ctx.db.scalar(
        select(Report).where(Report.case_id == case.id, Report.organization_id == ctx.org_id, Report.kind == body.kind, Report.status.in_(("queued", "processing")))
        .order_by(Report.created_at.desc())
    )
    if live is not None and not _stale(live):
        return _report(live)
    enforce_expensive_limit("report", ctx.org_id, ctx.user.id)
    r = Report(organization_id=ctx.org_id, case_id=case.id, kind=body.kind, requested_by=ctx.user.id)
    ctx.db.add(r)
    ctx.db.flush()
    ctx.db.add(CaseEvent(organization_id=ctx.org_id, case_id=case.id, kind="report_requested", summary=f"{body.kind.capitalize()} report requested.", actor_id=ctx.user.id))
    audit.record(ctx.db, ctx.org_id, "report.requested", actor=ctx.user, object_type="report", object_id=r.id, metadata={"case_id": str(case.id), "kind": body.kind})
    outbox.enqueue(ctx.db, "app.workers.tasks.build_report", [str(ctx.org_id), str(r.id)], queue="reports")
    ctx.db.commit()
    outbox.flush()
    ctx.db.refresh(r)
    return _report(r)


def _stale(r: Report) -> bool:
    return r.status == "processing" and r.started_at is not None and utcnow() - r.started_at > STALE_AFTER


@router.post("/reports/{report_id}/retry", status_code=202)
def retry_report(report_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    """Safe to call repeatedly: only a failed job, or one whose worker vanished, is re-queued."""
    r = get_owned(ctx, Report, report_id)
    if r.status not in ("failed",) and not _stale(r):
        return _report(r)
    enforce_expensive_limit("report", ctx.org_id, ctx.user.id)
    r.status, r.error, r.error_code, r.completed_at, r.started_at = "queued", "", "", None, None
    ctx.db.add(CaseEvent(organization_id=ctx.org_id, case_id=r.case_id, kind="report_retried", summary=f"{r.kind.capitalize()} report retried.", actor_id=ctx.user.id))
    audit.record(ctx.db, ctx.org_id, "report.retried", actor=ctx.user, object_type="report", object_id=r.id, metadata={"case_id": str(r.case_id), "attempts": r.attempts})
    outbox.enqueue(ctx.db, "app.workers.tasks.build_report", [str(ctx.org_id), str(r.id)], queue="reports")
    ctx.db.commit()
    outbox.flush()
    ctx.db.refresh(r)
    return _report(r)


@router.get("/reports")
def list_all_reports(limit: int = 50, offset: int = 0, ctx: Ctx = Depends(viewer)):
    stmt = (
        select(Report, Case.number, Case.title)
        .join(Case, Case.id == Report.case_id)
        .where(Report.organization_id == ctx.org_id)
        .order_by(Report.created_at.desc())
        .limit(max(1, min(limit, 100)))
        .offset(max(0, offset))
    )
    total = ctx.db.scalar(select(func.count()).select_from(Report).where(Report.organization_id == ctx.org_id)) or 0
    items = [{**_report(r), "case_reference": f"VEY-{n:04d}", "case_title": t} for r, n, t in ctx.db.execute(stmt)]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/cases/{case_id}/reports")
def list_reports(case_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    case = get_owned(ctx, Case, case_id)
    rows = ctx.db.scalars(select(Report).where(Report.case_id == case.id, Report.organization_id == ctx.org_id).order_by(Report.created_at.desc()))
    return {"items": [_report(r) for r in rows]}


@router.get("/reports/{report_id}")
def get_report(report_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    return _report(get_owned(ctx, Report, report_id))


@router.get("/reports/{report_id}/download")
def download_report(report_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    r = get_owned(ctx, Report, report_id)
    if r.status != "completed":
        raise HTTPException(status_code=409, detail=f"Report is {r.status}")
    try:
        data = storage().read(ctx.org_id, r.storage_key)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Stored report is missing")
    audit.record(ctx.db, ctx.org_id, "report.downloaded", actor=ctx.user, object_type="report", object_id=r.id, metadata={"case_id": str(r.case_id)})
    ctx.db.commit()
    return Response(
        content=data, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="veylith-report-{str(r.id)[:8]}.pdf"', "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"},
    )
