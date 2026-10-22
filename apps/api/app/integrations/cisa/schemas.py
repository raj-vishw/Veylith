"""Validation of the CISA Known Exploited Vulnerabilities catalogue envelope."""

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..base import IngestionError


class KevCatalog(BaseModel):
    model_config = ConfigDict(extra="allow")
    title: str | None = None
    catalogVersion: str = Field(default="", max_length=100)
    dateReleased: str | None = None
    count: int | None = Field(default=None, ge=0)
    vulnerabilities: list[dict]


def validate_catalog(data: object) -> KevCatalog:
    if not isinstance(data, dict):
        raise IngestionError("KEV catalogue is not a JSON object")
    try:
        catalog = KevCatalog.model_validate(data)
    except ValidationError as exc:
        raise IngestionError(f"KEV catalogue failed schema validation: {exc.errors()[0]['loc']}") from exc
    # A declared count that disagrees with the payload means a truncated or tampered download.
    if catalog.count is not None and catalog.count != len(catalog.vulnerabilities):
        raise IngestionError(f"KEV catalogue declares {catalog.count} records but contains {len(catalog.vulnerabilities)}")
    return catalog
