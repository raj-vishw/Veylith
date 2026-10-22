"""Advisory ingestion from fixed, trusted sources (NVD, CISA KEV) and bundled synthetic fixtures.

Safety properties:
  * endpoints come from configuration only; no user-supplied URL is ever fetched (no SSRF surface)
  * bounded retries with backoff, honouring Retry-After
  * idempotent: unchanged upstream content is detected by hash and skipped
  * raw upstream payloads are stored separately from normalised fields
  * advisory text is stored as data and never interpreted or executed"""

import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..integrations.base import AffectedEntry, IngestionError, NormalizedAdvisory, _date, _dt, _severity, content_hash  # noqa: F401
from ..integrations.cisa.mapper import map_item as parse_kev_item  # noqa: F401
from ..integrations.http import fetch_json  # noqa: F401
from ..integrations.nvd.mapper import map_item as parse_nvd_item  # noqa: F401
from ..models import (
    Advisory,
    AdvisoryRevision,
    AffectedProduct,
    IngestionRun,
    SourceRecord,
    utcnow,
)
from .matching import normalize_name

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"
NVD_MAX_WINDOW = timedelta(days=119)  # NVD rejects date ranges over 120 days



# --------------------------------------------------------------------------- parsing


# --------------------------------------------------------------------------- persistence
def _affected_rows(advisory_pk: uuid.UUID, entries: list[AffectedEntry]) -> list[AffectedProduct]:
    rows = []
    for e in entries:
        if not e.vulnerable:
            continue
        rows.append(
            AffectedProduct(
                advisory_id=advisory_pk, cpe=e.cpe, vendor=e.vendor, product=e.product,
                vendor_norm=normalize_name(e.vendor, vendor=True), product_norm=normalize_name(e.product),
                exact_version=e.exact_version, start_including=e.start_including, start_excluding=e.start_excluding,
                end_including=e.end_including, end_excluding=e.end_excluding, vulnerable=True,
            )
        )
    return rows


def _correlation_hash(adv: Advisory, affected: list[AffectedEntry] | list[AffectedProduct]) -> str:
    return content_hash(
        {
            "severity": adv.severity, "cvss": adv.cvss_score, "kev": adv.known_exploited, "mitigation": adv.mitigation,
            "affected": sorted(
                [a.cpe, a.vendor, a.product, a.exact_version, a.start_including, a.start_excluding, a.end_including, a.end_excluding]
                for a in affected
            ),
        }
    )


def upsert_advisory(db: Session, adv: NormalizedAdvisory, raw: dict, *, synthetic: bool = False, retrieved_at: datetime | None = None) -> str:
    """Returns 'new', 'updated' or 'unchanged'. Safe to call repeatedly with the same payload."""
    retrieved_at = retrieved_at or utcnow()
    raw_hash = content_hash(raw)
    record = db.scalar(select(SourceRecord).where(SourceRecord.source == adv.source, SourceRecord.external_id == adv.advisory_id))
    if record is not None and record.content_hash == raw_hash:
        return "unchanged"
    if record is None:
        db.add(SourceRecord(source=adv.source, external_id=adv.advisory_id, source_url=adv.source_url, content_hash=raw_hash, raw=raw, retrieved_at=retrieved_at))
    else:
        record.content_hash, record.raw, record.retrieved_at = raw_hash, raw, retrieved_at

    existing = db.scalar(select(Advisory).where(Advisory.advisory_id == adv.advisory_id))
    if existing is None:
        row = Advisory(
            advisory_id=adv.advisory_id, source=adv.source, title=adv.title[:500], description=adv.description,
            published_at=adv.published_at, modified_at=adv.modified_at, severity=adv.severity, cvss_score=adv.cvss_score,
            known_exploited=adv.known_exploited, kev_added_at=adv.kev_added_at, kev_due_date=adv.kev_due_date,
            mitigation=adv.mitigation, references=adv.references, source_url=adv.source_url, is_synthetic=synthetic,
            first_seen_at=retrieved_at, last_ingested_at=retrieved_at,
        )
        db.add(row)
        db.flush()
        db.add_all(_affected_rows(row.id, adv.affected))
        db.flush()
        row.content_hash = _correlation_hash(row, [a for a in adv.affected if a.vulnerable])
        return "new"

    changes: dict = {}
    if adv.source.endswith("kev"):
        # KEV only contributes exploitation facts and a required action; it must not clobber NVD detail.
        updates: dict[str, Any] = {"known_exploited": True, "kev_added_at": adv.kev_added_at, "kev_due_date": adv.kev_due_date}
        if not existing.mitigation:
            updates["mitigation"] = adv.mitigation
        if not existing.description:
            updates["description"] = adv.description
        replace_affected = False
    else:
        updates = {
            "source": adv.source, "title": adv.title[:500], "description": adv.description, "published_at": adv.published_at,
            "modified_at": adv.modified_at, "severity": adv.severity, "cvss_score": adv.cvss_score,
            "mitigation": adv.mitigation or existing.mitigation, "references": adv.references, "source_url": adv.source_url,
        }
        if adv.known_exploited:
            updates.update(known_exploited=True, kev_added_at=adv.kev_added_at, kev_due_date=adv.kev_due_date)
        replace_affected = True
    for key, new in updates.items():
        old = getattr(existing, key)
        if old != new:
            if key in ("description", "severity", "cvss_score", "known_exploited", "mitigation", "modified_at"):
                changes[key] = {"from": _short(old), "to": _short(new)}
            setattr(existing, key, new)
    existing.last_ingested_at = retrieved_at
    current = list(db.scalars(select(AffectedProduct).where(AffectedProduct.advisory_id == existing.id)))
    if replace_affected and adv.affected:
        old_set = sorted([a.cpe, a.vendor, a.product, a.exact_version, a.start_including, a.start_excluding, a.end_including, a.end_excluding] for a in current)
        new_rows = _affected_rows(existing.id, adv.affected)
        new_set = sorted([a.cpe, a.vendor, a.product, a.exact_version, a.start_including, a.start_excluding, a.end_including, a.end_excluding] for a in new_rows)
        if old_set != new_set:
            changes["affected_products"] = {"from": len(old_set), "to": len(new_set)}
            db.execute(delete(AffectedProduct).where(AffectedProduct.advisory_id == existing.id))
            db.add_all(new_rows)
            current = new_rows
    elif not current and adv.affected:
        rows = _affected_rows(existing.id, adv.affected)
        db.add_all(rows)
        current = rows
        changes["affected_products"] = {"from": 0, "to": len(rows)}
    db.flush()
    new_hash = _correlation_hash(existing, current)
    if new_hash != existing.content_hash:
        existing.content_hash = new_hash
    if changes:
        db.add(AdvisoryRevision(advisory_id=existing.id, changes=changes))
    return "updated"


def _short(v):
    if isinstance(v, str) and len(v) > 200:
        return v[:200] + "…"
    return v.isoformat() if hasattr(v, "isoformat") else v


# --------------------------------------------------------------------------- HTTP

# --------------------------------------------------------------------------- runs
def _finish(db: Session, run: IngestionRun, error: str = "", status: str | None = None) -> IngestionRun:
    run.finished_at = utcnow()
    run.status = status or ("failed" if error else "succeeded")
    run.error = error[:2000]
    db.commit()
    return run


def start_run(db: Session, source: str, triggered_by=None) -> IngestionRun:
    run = IngestionRun(source=source, triggered_by=triggered_by)
    db.add(run)
    db.commit()
    return run


def _ingest_items(db: Session, run: IngestionRun, items, parse, raw_of, *, validate=None, synthetic=False) -> set[uuid.UUID]:
    """Normalise and upsert records one at a time. A malformed record is counted as rejected and skipped; a
    concurrent writer that inserted the same advisory first (unique violation) causes one retry, which then sees an update."""
    changed: set[uuid.UUID] = set()
    for item in items:
        run.records_seen += 1
        adv = None
        outcome = "rejected"
        for attempt in (1, 2):
            try:
                with db.begin_nested():  # one malformed record must not abort the batch
                    if validate:
                        validate(item)
                    adv = parse(item)
                    outcome = upsert_advisory(db, adv, raw_of(item), synthetic=synthetic)
                break
            except IngestionError:
                outcome = "rejected"
                break
            except IntegrityError:
                outcome = "rejected" if attempt == 2 else "retry"
        if outcome == "rejected":
            run.records_rejected += 1
            continue
        if outcome == "new":
            run.records_new += 1
        elif outcome == "updated":
            run.records_updated += 1
        if outcome != "unchanged" and adv is not None:
            row = db.scalar(select(Advisory.id).where(Advisory.advisory_id == adv.advisory_id))
            if row:
                changed.add(row)
    db.commit()
    return changed


def ingest_nvd(db: Session, client: httpx.Client, run: IngestionRun, *, since: datetime | None = None, sleep=time.sleep) -> set[uuid.UUID]:
    from ..integrations.nvd.client import NvdClient
    from ..integrations.nvd.schemas import validate_record

    now = datetime.now(UTC)
    start = since or (now - timedelta(days=3))
    run.window_start = start
    run.attempts += 1
    changed: set[uuid.UUID] = set()
    try:
        for records in NvdClient(client, sleep=sleep).pages(start, now):
            changed |= _ingest_items(db, run, records, parse_nvd_item, lambda i: i, validate=validate_record)
    except IngestionError as exc:
        _finish(db, run, str(exc))
        return changed
    _finish(db, run)
    return changed


def ingest_kev(db: Session, client: httpx.Client, run: IngestionRun, *, sleep=time.sleep, force: bool = False) -> set[uuid.UUID]:
    from ..integrations.cisa.client import fetch_catalog

    run.attempts += 1
    try:
        catalog = fetch_catalog(client, sleep=sleep)
        run.catalog_version = catalog.catalogVersion
        previous = db.scalar(
            select(IngestionRun)
            .where(IngestionRun.source == "kev", IngestionRun.status.in_(("succeeded", "skipped")), IngestionRun.id != run.id, IngestionRun.catalog_version != "")
            .order_by(IngestionRun.started_at.desc())
        )
        if not force and previous is not None and previous.catalog_version == catalog.catalogVersion:
            run.records_seen = len(catalog.vulnerabilities)
            _finish(db, run, status="skipped")  # the catalogue has not changed since the last successful pull
            return set()
        changed = _ingest_items(db, run, catalog.vulnerabilities, parse_kev_item, lambda i: i)
    except IngestionError as exc:
        _finish(db, run, str(exc))
        return set()
    _finish(db, run)
    return changed


def ingest_fixture(db: Session, run: IngestionRun, name: str = "synthetic") -> set[uuid.UUID]:
    """Loads bundled synthetic advisories (clearly labelled as such) for demos and offline tests."""
    changed: set[uuid.UUID] = set()
    nvd = json.loads((FIXTURE_DIR / f"{name}_nvd.json").read_text(encoding="utf-8"))
    kev = json.loads((FIXTURE_DIR / f"{name}_kev.json").read_text(encoding="utf-8"))
    try:
        changed |= _ingest_items(db, run, nvd.get("vulnerabilities", []), lambda i: parse_nvd_item(i, source="fixture"), lambda i: i, synthetic=True)
        changed |= _ingest_items(db, run, kev.get("vulnerabilities", []), lambda i: _as_fixture(parse_kev_item(i)), lambda i: i, synthetic=True)
    except IngestionError as exc:
        _finish(db, run, str(exc))
        return changed
    _finish(db, run)
    return changed


def _as_fixture(adv: NormalizedAdvisory) -> NormalizedAdvisory:
    adv.source = "fixture-kev"
    return adv


def last_successful_start(db: Session, source: str) -> datetime | None:
    run = db.scalar(select(IngestionRun).where(IngestionRun.source == source, IngestionRun.status.in_(("succeeded", "skipped"))).order_by(IngestionRun.started_at.desc()))
    return run.started_at - timedelta(minutes=5) if run else None
