"""Source-neutral objects shared by every intelligence connector.

Connectors translate an external format into NormalizedAdvisory; the rest of Veylith only ever sees these objects."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime


class IngestionError(Exception):
    pass


@dataclass
class AffectedEntry:
    cpe: str = ""
    vendor: str = ""
    product: str = ""
    exact_version: str = ""
    start_including: str = ""
    start_excluding: str = ""
    end_including: str = ""
    end_excluding: str = ""
    vulnerable: bool = True


@dataclass
class NormalizedAdvisory:
    advisory_id: str
    source: str
    title: str = ""
    description: str = ""
    published_at: datetime | None = None
    modified_at: datetime | None = None
    severity: str = "unknown"
    cvss_score: float | None = None
    known_exploited: bool = False
    kev_added_at: date | None = None
    kev_due_date: date | None = None
    mitigation: str = ""
    references: list = field(default_factory=list)
    source_url: str = ""
    affected: list[AffectedEntry] = field(default_factory=list)


# --------------------------------------------------------------------------- helpers
def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _date(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def content_hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def _severity(score: float | None, label: str | None) -> str:
    if label and label.lower() in ("low", "medium", "high", "critical"):
        return label.lower()
    if score is None:
        return "unknown"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"

