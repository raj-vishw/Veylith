"""Investigation report generation: authorised server-side data -> controlled HTML template -> PDF.

The PDF step needs WeasyPrint and its system libraries, which exist only in the dedicated reporter image.
Templates are fixed files with autoescaping on; user-supplied text is only ever inserted as escaped text."""

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import (
    Advisory,
    Case,
    CaseAssessment,
    CaseEvent,
    CaseNote,
    Client,
    Evidence,
    ImpactAssessment,
    Organization,
    Product,
    Report,
    Task,
    User,
    Vendor,
    utcnow,
)
from . import audit
from .storage import storage

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True, trim_blocks=True, lstrip_blocks=True)

STATE_LABELS = {
    "potential_impact": "Potential impact (not confirmed)",
    "insufficient_data": "Insufficient data",
    "confirmed_dependency": "Confirmed dependency",
    "exposure_verified": "Exposure verified",
    "compromise_confirmed": "Compromise confirmed",
    "no_match_found": "No match found",
}


TEMPLATE_VERSION = "2"
STALE_AFTER = timedelta(minutes=15)  # a job "processing" for longer than this lost its worker and may be retried

# Safe, user-facing explanation per error category. Raw exception text stays in the database and the worker log only.
ERROR_MESSAGES = {
    "pdf_unavailable": "PDF rendering is not available right now. Try again later or contact an administrator.",
    "case_unavailable": "The case for this report could not be found.",
    "storage_failed": "The finished report could not be stored. Try again.",
    "timeout": "Report generation took too long and was stopped. Try again.",
    "render_failed": "The report could not be generated. Try again; contact an administrator if it keeps failing.",
}


class PdfUnavailable(RuntimeError):
    pass


def classify(exc: BaseException) -> str:
    if isinstance(exc, PdfUnavailable):
        return "pdf_unavailable"
    if isinstance(exc, LookupError):
        return "case_unavailable"
    if type(exc).__name__ in ("SoftTimeLimitExceeded", "TimeLimitExceeded", "TimeoutError"):
        return "timeout"
    if isinstance(exc, OSError):
        return "storage_failed"
    return "render_failed"


def collect(db: Session, org_id: uuid.UUID, case_id: uuid.UUID, kind: str, generated_by: str, report_ref: str) -> dict:
    """Everything is read through the tenant-scoped session and filtered by organization again here."""
    s = get_settings()
    limit = s.max_report_items
    case = db.scalar(select(Case).where(Case.id == case_id, Case.organization_id == org_id))
    if case is None:
        raise LookupError("case not found")
    org = db.get(Organization, org_id)
    client = db.get(Client, case.client_id) if case.client_id else None
    assignee = db.get(User, case.assignee_id) if case.assignee_id else None
    advisory = db.get(Advisory, case.advisory_id) if case.advisory_id else None

    assessments = []
    rows = db.execute(
        select(ImpactAssessment, Advisory, Product, Vendor)
        .join(CaseAssessment, CaseAssessment.assessment_id == ImpactAssessment.id)
        .join(Advisory, Advisory.id == ImpactAssessment.advisory_id)
        .join(Product, Product.id == ImpactAssessment.product_id)
        .join(Vendor, Vendor.id == ImpactAssessment.vendor_id)
        .where(CaseAssessment.case_id == case.id, ImpactAssessment.organization_id == org_id)
    ).all()
    for a, adv, product, vendor in rows[:limit]:
        assessments.append(
            {
                "advisory": adv.advisory_id, "title": adv.title, "severity": adv.severity, "known_exploited": adv.known_exploited,
                "source": adv.source, "source_url": adv.source_url, "synthetic": adv.is_synthetic,
                "published_at": adv.published_at, "mitigation": adv.mitigation,
                "vendor": vendor.name, "product": f"{product.name} {product.version}".strip(),
                "state": a.state, "state_label": STATE_LABELS.get(a.state, a.state), "match_type": a.match_type, "version_status": a.version_status,
                "priority": a.priority, "factors": a.priority_factors, "unknowns": a.unknowns, "steps": a.recommended_steps,
                "path": a.evidence.get("path", []), "known": a.evidence.get("known", []),
                "confidence": {"Source": a.source_confidence, "Match": a.match_confidence, "Relationship": a.relationship_confidence, "Impact": a.impact_confidence},
            }
        )
    assets = {}
    for item in assessments:
        for step in item["path"]:
            if step.get("step") == "asset":
                assets[step["label"]] = step.get("criticality", "")

    tasks = [
        {"title": t.title, "status": t.status, "priority": t.priority, "due_date": t.due_date, "completion_notes": t.completion_notes,
         "completed_at": t.completed_at, "verification": t.verification_status, "verified_at": t.verified_at, "verification_notes": t.verification_notes}
        for t in db.scalars(select(Task).where(Task.case_id == case.id, Task.organization_id == org_id).order_by(Task.created_at).limit(limit))
    ]
    timeline_total = db.scalar(select(func.count()).select_from(CaseEvent).where(CaseEvent.case_id == case.id)) or 0
    timeline = [
        {"occurred_at": e.occurred_at, "summary": e.summary, "system": e.is_system}
        for e in db.scalars(select(CaseEvent).where(CaseEvent.case_id == case.id, CaseEvent.organization_id == org_id).order_by(CaseEvent.occurred_at).limit(limit))
    ]
    evidence = [
        {"title": e.title, "kind": e.kind, "source_name": e.source_name, "source_url": e.source_url, "excerpt": (e.excerpt or "")[:1500],
         "filename": e.original_filename, "sha256": e.sha256, "verification": e.verification_status, "retrieved_at": e.retrieved_at,
         "collected_at": e.collected_at}
        for e in db.scalars(select(Evidence).where(Evidence.case_id == case.id, Evidence.organization_id == org_id, Evidence.deleted_at.is_(None)).order_by(Evidence.retrieved_at).limit(limit))
    ]
    # Internal analyst notes never go into a client-facing report.
    notes = [
        {"created_at": n.created_at, "body": n.body}
        for n in db.scalars(select(CaseNote).where(CaseNote.case_id == case.id, CaseNote.organization_id == org_id, CaseNote.visibility == "customer").order_by(CaseNote.created_at).limit(limit))
    ]

    confirmed_states = {"confirmed_dependency", "exposure_verified", "compromise_confirmed"}
    return {
        "kind": kind, "reference": report_ref, "generated_at": datetime.now(UTC), "generated_by": generated_by,
        "organization": org.name, "client": client.name if client else "Not specified",
        "case": {
            "reference": f"VEY-{case.number:04d}", "title": case.title, "description": case.description, "status": case.status,
            "priority": case.priority, "severity": case.severity or "Not stated", "assignee": (assignee.display_name or assignee.email) if assignee else "Unassigned",
            "due_date": case.due_date, "closure_reason": case.closure_reason, "resolution_summary": case.resolution_summary,
            "created_at": case.created_at,
        },
        "advisory": {"id": advisory.advisory_id, "title": advisory.title, "description": advisory.description, "url": advisory.source_url,
                     "published_at": advisory.published_at, "severity": advisory.severity} if advisory else None,
        "assessments": assessments,
        "confirmed": [a for a in assessments if a["state"] in confirmed_states],
        "potential": [a for a in assessments if a["state"] not in confirmed_states],
        "assets": [{"label": k, "criticality": v} for k, v in assets.items()],
        "tasks": tasks,
        "tasks_done": sum(1 for t in tasks if t["status"] == "done"),
        "tasks_verified": sum(1 for t in tasks if t["verification"] == "verified"),
        "tasks_unverified_done": sum(1 for t in tasks if t["status"] == "done" and t["verification"] != "verified"),
        "template_version": TEMPLATE_VERSION,
        "tasks_open": sum(1 for t in tasks if t["status"] in ("open", "in_progress", "blocked")),
        "timeline": timeline, "timeline_truncated": timeline_total > len(timeline),
        "evidence": evidence, "notes": notes,
        "has_synthetic": any(a["synthetic"] for a in assessments) or bool(org.is_demo),
        "truncated": len(rows) > limit,
    }


def render_html(data: dict) -> str:
    return _env.get_template("report.html.j2").render(**data)


def render_pdf(html: str) -> bytes:
    try:
        from weasyprint import HTML  # only present in the reporter image
        from weasyprint.urls import URLFetcher
    except Exception as exc:  # ImportError, or missing system libraries
        raise PdfUnavailable("PDF rendering is not available in this environment") from exc

    # Only inline data: URLs may be loaded. http(s), file and ftp are refused, so a template or user text can
    # never make the renderer reach the network or the filesystem (SSRF / local file disclosure).
    fetcher = URLFetcher(allowed_protocols=["data"], allow_redirects=False, timeout=1, fail_on_errors=False)
    return HTML(string=html, base_url=None, url_fetcher=fetcher).write_pdf()


def claim(db: Session, org_id: uuid.UUID, report_id: uuid.UUID) -> Report | None:
    """Take the job for this worker. Returns None when there is nothing to do: already completed (a redelivered message),
    or another worker is processing it. The row lock makes two concurrent deliveries pick exactly one winner."""
    report = db.scalar(select(Report).where(Report.id == report_id, Report.organization_id == org_id).with_for_update())
    if report is None:
        raise LookupError("report not found")
    if report.status == "completed":
        return None
    if report.status == "processing" and report.started_at and utcnow() - report.started_at < STALE_AFTER:
        return None
    report.status, report.started_at, report.attempts, report.error, report.error_code = "processing", utcnow(), report.attempts + 1, "", ""
    db.commit()
    return report


def generate(db: Session, org_id: uuid.UUID, report_id: uuid.UUID, *, renderer=None) -> Report:
    """db must be scoped to org_id. Idempotent: a redelivered or duplicate task never produces a second PDF.
    Ends completed or failed; never leaves a claimed job pending."""
    report = claim(db, org_id, report_id)
    if report is None:
        current = db.scalar(select(Report).where(Report.id == report_id, Report.organization_id == org_id))
        assert current is not None
        return current
    requester = db.get(User, report.requested_by) if report.requested_by else None
    try:
        data = collect(db, org_id, report.case_id, report.kind, requester.email if requester else "system", f"RPT-{str(report.id)[:8].upper()}")
        pdf = (renderer or render_pdf)(render_html(data))
        key, digest = storage().put(org_id, pdf)
        report.storage_key, report.sha256, report.size_bytes, report.template_version = key, digest, len(pdf), TEMPLATE_VERSION
        report.status, report.error, report.error_code = "completed", "", ""
        audit.record(db, org_id, "report.generated", actor=requester, object_type="report", object_id=report.id,
                     metadata={"case_id": str(report.case_id), "kind": report.kind, "sha256": digest, "template_version": TEMPLATE_VERSION})
        db.add(CaseEvent(organization_id=org_id, case_id=report.case_id, kind="report_generated", is_system=True,
                         summary=f"{report.kind.capitalize()} report generated (SHA-256 {digest[:12]}…).", data={"report_id": str(report.id)}))
    except Exception as exc:
        db.rollback()
        failed = db.scalar(select(Report).where(Report.id == report_id, Report.organization_id == org_id))
        assert failed is not None
        report = failed
        code = classify(exc)
        report.status, report.error_code, report.error = "failed", code, f"{type(exc).__name__}: {exc}"[:500]
        audit.record(db, org_id, "report.failed", actor=requester, object_type="report", object_id=report.id,
                     metadata={"case_id": str(report.case_id), "error_code": code})
        db.add(CaseEvent(organization_id=org_id, case_id=report.case_id, kind="report_failed", is_system=True,
                         summary=f"{report.kind.capitalize()} report failed ({code}).", data={"report_id": str(report.id)}))
    report.completed_at = utcnow()
    db.commit()
    return report
