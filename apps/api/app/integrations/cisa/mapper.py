"""Maps a CISA Known Exploited Vulnerabilities record to a NormalizedAdvisory."""

from ..base import AffectedEntry, IngestionError, NormalizedAdvisory, _date


def map_item(item: dict) -> NormalizedAdvisory:
    cve_id = item.get("cveID")
    if not cve_id:
        raise IngestionError("KEV record without cveID")
    adv = NormalizedAdvisory(
        advisory_id=cve_id, source="kev", title=item.get("vulnerabilityName") or cve_id,
        description=item.get("shortDescription", ""), known_exploited=True,
        kev_added_at=_date(item.get("dateAdded")), kev_due_date=_date(item.get("dueDate")),
        mitigation=item.get("requiredAction", ""), source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    )
    vendor, product = item.get("vendorProject", ""), item.get("product", "")
    if vendor and product:
        # KEV names the product but not versions, so the version is explicitly unknown ("?"), never "all versions".
        adv.affected.append(AffectedEntry(vendor=vendor, product=product, exact_version="?"))
    return adv


parse_kev_item = map_item
