"""Transactional outbox.

Background work that must happen *because a database change committed* (re-correlate after an inventory edit,
ingest after a request, render a report) is written to `outbox_events` in the SAME transaction as that change.
A dispatcher then hands pending rows to Celery. Consequences:

  * no change without its follow-up work: a crash between commit and enqueue cannot lose the job
  * no follow-up work without the change: a rolled-back request never enqueues anything
  * Redis being down only delays dispatch; rows stay pending and the periodic dispatcher retries them
  * tasks are at-least-once, so every task is written to be idempotent

`dedupe_key` collapses repeated requests (e.g. many inventory edits) into one pending job via a partial unique index.
"""

import logging
from datetime import timedelta

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import SessionLocal
from ..models import OutboxEvent, utcnow

log = logging.getLogger("veylith.outbox")
MAX_ATTEMPTS = 10  # then the event is left pending but flagged (see last_error) for an operator, not retried forever


def enqueue(db: Session, task: str, args: list, *, queue: str = "default", dedupe_key: str = "", delay_seconds: int = 0) -> None:
    """Record a job in the caller's transaction. Call before commit."""
    if get_settings().celery_eager:
        delay_seconds = 0  # tests and simple local runs execute inline
    values = {"task": task, "args": args, "queue": queue, "dedupe_key": dedupe_key, "available_at": utcnow() + timedelta(seconds=delay_seconds)}
    stmt = pg_insert(OutboxEvent).values(**values)
    if dedupe_key:
        # A pending job with the same key already covers this request: it will read current state when it runs.
        stmt = stmt.on_conflict_do_nothing(index_elements=["dedupe_key"], index_where=text("dispatched_at IS NULL AND dedupe_key <> ''"))
    db.execute(stmt)


def dispatch_pending(limit: int = 100) -> int:
    """Send due, undispatched events to the broker. Safe to run concurrently (rows are claimed with SKIP LOCKED)."""
    from ..workers import tasks  # noqa: F401  (registers task names)
    from ..workers.celery_app import celery

    sent = 0
    with SessionLocal() as db:
        rows = db.scalars(
            select(OutboxEvent)
            .where(OutboxEvent.dispatched_at.is_(None), OutboxEvent.available_at <= utcnow(), OutboxEvent.attempts < MAX_ATTEMPTS)
            .order_by(OutboxEvent.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).all()
        for row in rows:
            row.attempts += 1
            try:
                celery.tasks[row.task].apply_async(args=row.args, queue=row.queue)
                row.dispatched_at = utcnow()
                row.last_error = ""
                sent += 1
            except Exception as exc:  # broker unreachable, unknown task...: leave pending for the next pass
                row.last_error = f"{type(exc).__name__}: {exc}"[:500]
                log.warning("outbox dispatch failed for %s (attempt %s): %s", row.task, row.attempts, row.last_error)
            db.commit()  # commit per row so one failure never un-sends the others
    return sent


def flush() -> int:
    """Best-effort immediate dispatch after a request commits. Failures are left to the periodic dispatcher."""
    try:
        return dispatch_pending()
    except Exception:
        log.exception("outbox flush failed")
        return 0


def pending_count() -> int:
    with SessionLocal() as db:
        return len(db.scalars(select(OutboxEvent.id).where(OutboxEvent.dispatched_at.is_(None))).all())
