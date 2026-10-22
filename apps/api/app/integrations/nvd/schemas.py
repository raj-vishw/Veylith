"""Structural validation of NVD API 2.0 responses. Unknown fields are tolerated (the API grows); required ones are enforced."""

import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..base import IngestionError

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_RECORD_BYTES = 2 * 1024 * 1024


class NvdCve(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str = Field(min_length=8, max_length=40)
    published: str | None = None
    lastModified: str | None = None
    descriptions: list[dict] = []
    metrics: dict = {}
    configurations: list[dict] = []
    references: list[dict] = []


class NvdPage(BaseModel):
    model_config = ConfigDict(extra="allow")
    vulnerabilities: list = []  # records are validated one by one so a single bad entry cannot reject the page
    totalResults: int = Field(default=0, ge=0)
    resultsPerPage: int | None = None
    startIndex: int | None = None


def validate_page(data: object) -> NvdPage:
    if not isinstance(data, dict):
        raise IngestionError("NVD response is not a JSON object")
    try:
        return NvdPage.model_validate(data)
    except ValidationError as exc:
        raise IngestionError(f"NVD response failed schema validation: {exc.errors()[0]['loc']}") from exc


def validate_record(item: dict) -> None:
    """Raises IngestionError for a record that cannot be trusted enough to normalise."""
    cve = item.get("cve", item) if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        raise IngestionError("NVD record is not an object")
    try:
        parsed = NvdCve.model_validate(cve)
    except ValidationError as exc:
        raise IngestionError(f"NVD record failed validation: {exc.errors()[0]['loc']}") from exc
    if not CVE_ID.match(parsed.id):
        raise IngestionError(f"NVD record has an unexpected identifier: {parsed.id[:40]!r}")
    if len(str(cve)) > MAX_RECORD_BYTES:
        raise IngestionError(f"NVD record {parsed.id} is implausibly large")
