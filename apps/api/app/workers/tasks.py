import logging
import uuid

import httpx

from ..db import SessionLocal, org_session
from ..models import IngestionRun
from ..services import correlation, ingestion, reports
from .celery_app import celery

log = logging.getLogger("veylith.worker")


# NVD is rate limited (about 5 requests per 30 s without an API key), so a large window legitimately takes a while.
@celery.task(name="app.workers.tasks.ingest_source", autoretry_for=(), acks_late=True, soft_time_limit=3300, time_limit=3600)
def ingest_source(run_id: str, source: str) -> dict:
    """Fetch one source, then correlate every organization against the advisories that changed."""
    with SessionLocal() as db:
        run = db.get(IngestionRun, uuid.UUID(run_id))
        try:
            if source == "fixture":
                changed = ingestion.ingest_fixture(db, run)
            else:
                since = ingestion.last_successful_start(db, source)
                with httpx.Client(follow_redirects=False, headers={"User-Agent": "Veylith/1.0"}) as client:
                    changed = ingestion.ingest_nvd(db, client, run, since=since) if source == "nvd" else ingestion.ingest_kev(db, client, run)
        except Exception as exc:  # recorded so a failed feed is visible in the UI
            db.rollback()
            run = db.get(IngestionRun, uuid.UUID(run_id))
            ingestion._finish(db, run, f"unexpected error: {type(exc).__name__}: {exc}")
            log.exception("ingestion failed", extra={"source": source})
            return {"status": "failed"}
    if changed:
        correlation.correlate_all_orgs(SessionLocal, changed)
    log.info("ingestion finished", extra={"source": source, "changed": len(changed)})
    return {"status": "ok", "changed": len(changed)}


@celery.task(name="app.workers.tasks.dispatch_outbox")
def dispatch_outbox() -> dict:
    from ..services import outbox

    return {"sent": outbox.dispatch_pending()}


@celery.task(name="app.workers.tasks.scheduled_ingest", soft_time_limit=3300, time_limit=3600)
def scheduled_ingest(source: str) -> dict:
    with SessionLocal() as db:
        run = ingestion.start_run(db, source)
        run_id = str(run.id)
    return ingest_source(run_id, source)


@celery.task(name="app.workers.tasks.run_correlation", acks_late=True)
def run_correlation(org_id: str, actor_id: str | None = None) -> dict:

    from ..models import User
    oid = uuid.UUID(org_id)
    with org_session(oid) as db:
        actor = db.get(User, uuid.UUID(actor_id)) if actor_id else None
        run = correlation.correlate_org(db, oid, None, actor=actor)
        return {"status": run.status, "created": run.assessments_created, "updated": run.assessments_updated}


@celery.task(name="app.workers.tasks.build_report", acks_late=True, soft_time_limit=240, time_limit=300)
def build_report(org_id: str, report_id: str) -> dict:
    """Runs on the reporter queue, whose container has WeasyPrint installed."""
    oid = uuid.UUID(org_id)
    with org_session(oid) as db:
        report = reports.generate(db, oid, uuid.UUID(report_id))
        return {"status": report.status}
