"""Keeps assessments current: inventory changes queue a debounced correlation run for the organization.

The job is written to the transactional outbox in the SAME transaction as the inventory change, so it can neither be
lost (crash between commit and enqueue) nor fire for a change that rolled back. Repeated edits collapse into one
pending job per organization (dedupe key); that job reads the inventory when it runs, so it covers every edit made while it waited."""

import uuid

from sqlalchemy.orm import Session

from ..config import get_settings
from . import outbox


def schedule(db: Session, org_id: uuid.UUID) -> None:
    """Call BEFORE the commit of the inventory change."""
    s = get_settings()
    if not s.auto_correlate:
        return
    outbox.enqueue(db, "app.workers.tasks.run_correlation", [str(org_id), None], dedupe_key=f"correlate:{org_id}", delay_seconds=s.auto_correlate_delay_seconds)
