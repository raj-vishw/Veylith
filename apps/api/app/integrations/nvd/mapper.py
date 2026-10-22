"""Maps an NVD API 2.0 vulnerability record to a NormalizedAdvisory."""

from ...services.matching import parse_cpe
from ..base import AffectedEntry, IngestionError, NormalizedAdvisory, _date, _dt, _severity


def map_item(item: dict, source: str = "nvd") -> NormalizedAdvisory:
    cve = item.get("cve", item)
    cve_id = cve.get("id")
    if not cve_id or not isinstance(cve_id, str):
        raise IngestionError("NVD record without an id")
    description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, label = None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(key)
        if metrics:
            data = metrics[0].get("cvssData", {})
            score = data.get("baseScore")
            label = data.get("baseSeverity") or metrics[0].get("baseSeverity")
            break
    affected: list[AffectedEntry] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parsed = parse_cpe(m.get("criteria", ""))
                if not parsed or parsed.part not in ("a", "o", "h"):
                    continue
                affected.append(
                    AffectedEntry(
                        cpe=m["criteria"], vendor=parsed.vendor, product=parsed.product,
                        exact_version="" if parsed.version in ("*", "-") else parsed.version,
                        start_including=m.get("versionStartIncluding", ""), start_excluding=m.get("versionStartExcluding", ""),
                        end_including=m.get("versionEndIncluding", ""), end_excluding=m.get("versionEndExcluding", ""),
                        vulnerable=bool(m.get("vulnerable", True)),
                    )
                )
    refs = [{"url": r.get("url"), "source": r.get("source", "")} for r in cve.get("references", []) if r.get("url")][:25]
    mitigation = "\n".join(
        r["url"] for r in cve.get("references", []) if r.get("url") and any(t in (r.get("tags") or []) for t in ("Patch", "Mitigation", "Vendor Advisory"))
    )[:4000]
    adv = NormalizedAdvisory(
        advisory_id=cve_id, source=source, title=cve.get("cisaVulnerabilityName") or cve_id, description=description,
        published_at=_dt(cve.get("published")), modified_at=_dt(cve.get("lastModified")),
        severity=_severity(score, label), cvss_score=float(score) if score is not None else None,
        mitigation=mitigation, references=refs, source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", affected=affected,
    )
    if cve.get("cisaExploitAdd"):
        adv.known_exploited = True
        adv.kev_added_at = _date(cve.get("cisaExploitAdd"))
        adv.kev_due_date = _date(cve.get("cisaActionDue"))
    return adv


parse_nvd_item = map_item
