"""Correlation: advisories x inventory x graph -> evidence-backed impact assessments.

Pipeline per organization (all deterministic, no machine learning):
  1. normalise identifiers and find candidate advisory entries by vendor
  2. match product identity and evaluate the observed version against the advisory's ranges   -> AdvisoryMatch
  3. traverse recorded relationships (bounded depth, cycle-safe) from the product to client assets
  4. create/update one ImpactAssessment per (advisory, product, client) with evidence and uncertainty
     and snapshot the reasoning as AssessmentEvidence rows

The engine only ever produces match status `matched`, `needs_review` or `insufficient_data` (and `no_match` when a
previous match stops holding). Exposure, compromise and dependency confirmation are analyst decisions and are never
overwritten by recalculation."""

import uuid
from collections import defaultdict, deque

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import (
    Advisory,
    AdvisoryMatch,
    AffectedProduct,
    AssessmentEvent,
    AssessmentEvidence,
    CorrelationRun,
    ImpactAssessment,
    Organization,
    Product,
    SourceRecord,
    Vendor,
    utcnow,
)
from . import audit
from . import graph as gsvc
from .matching import MATCHER_VERSION, AffectedSpec, InventoryProduct, best_match, inventory_keys

SEV_POINTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
CRIT_POINTS = {"critical": 3, "high": 2, "medium": 1, "low": 0}
ACCESS_POINTS = {"admin": 2, "write": 2, "read": 1, "none": 0}
MATCH_QUALITY = {"cpe": 1, "name": 0, "alias": 0, "fuzzy": -1}
ASSESSMENT_MATCH_STATUS = {"matched": "matched", "needs_review": "needs_review", "insufficient_data": "insufficient_data"}


def derive_state(a: ImpactAssessment) -> str:
    """Single summary state from the separate status dimensions (kept for display, filtering and reports)."""
    if a.compromise_status == "confirmed":
        return "compromise_confirmed"
    if a.exposure_status == "verified":
        return "exposure_verified"
    if a.dependency_confirmed:
        return "confirmed_dependency"
    if a.match_status == "no_match":
        return "no_match_found"
    return "potential_impact" if a.match_status == "matched" else "insufficient_data"


def _spec(ap: AffectedProduct) -> AffectedSpec:
    return AffectedSpec(
        cpe=ap.cpe, vendor_norm=ap.vendor_norm, product_norm=ap.product_norm, exact_version=ap.exact_version,
        start_including=ap.start_including, start_excluding=ap.start_excluding, end_including=ap.end_including, end_excluding=ap.end_excluding,
    )


def _inventory(p: Product, v: Vendor) -> InventoryProduct:
    return InventoryProduct(
        vendor_name=v.name, vendor_aliases=tuple(v.aliases or ()), name=p.name, aliases=tuple(p.aliases or ()),
        package_name=p.package_name, version=p.version, cpe=p.cpe, ecosystem=p.ecosystem or "generic",
    )


# --------------------------------------------------------------------------- relationship traversal
def _rel(r, label: str, scope: str = "", hop: int = 1) -> dict:
    return {
        "id": str(r.id), "type": r.rel_type, "label": label, "verification_status": r.verification_status,
        "confidence": r.confidence, "access_scope": scope or r.access_scope, "hop": hop,
    }


def client_links(g: gsvc.Graph, vendor_id: uuid.UUID, product_id: uuid.UUID, max_depth: int | None = None) -> dict:
    """Per-client linkage for a product: recorded relationship chains from the product/vendor to client assets.

    Depth 1 = the product/vendor is used by (or has access to) an asset directly; each further hop follows
    `asset DEPENDS_ON asset` to the assets that depend on an affected one. The walk is bounded by max_depth, visits
    each asset once (so cycles terminate), ignores disputed relationships and flags stale ones.
    Access is never inferred: a vendor only 'has access' where a HAS_ACCESS_TO/CONNECTS_TO/HOSTS edge is recorded."""
    max_depth = max_depth or get_settings().max_traversal_depth
    links: dict[uuid.UUID | None, dict] = defaultdict(lambda: {"assets": {}, "relationships": [], "vendor_level": False, "hops": {}})
    vendor = g.vendors[vendor_id]
    ignored = {"disputed": 0}

    def usable(r) -> bool:
        if r.verification_status == "disputed":
            ignored["disputed"] += 1
            return False
        return True

    frontier: deque[tuple[uuid.UUID, int]] = deque()
    seen_assets: set[uuid.UUID] = set()

    def reach(asset, r, label: str, hop: int, scope: str = ""):
        slot = links[asset.client_id]
        slot["assets"][asset.id] = asset
        slot["hops"][asset.id] = min(hop, slot["hops"].get(asset.id, hop))
        slot["relationships"].append(_rel(r, label, scope, hop))
        if asset.id not in seen_assets:
            seen_assets.add(asset.id)
            frontier.append((asset.id, hop))

    for r in sorted(g.rels, key=lambda x: str(x.id)):  # sorted: deterministic output
        if r.rel_type == "USES_VENDOR" and r.target_id == vendor_id and r.source_id in g.clients and usable(r):
            slot = links[r.source_id]
            slot["vendor_level"] = True
            slot["relationships"].append(_rel(r, f"{g.clients[r.source_id].name} uses {vendor.name}", hop=0))
        elif r.rel_type == "DEPENDS_ON" and r.source_type == "asset" and r.source_id in g.assets and (
            (r.target_type == "product" and r.target_id == product_id) or (r.target_type == "vendor" and r.target_id == vendor_id)
        ) and usable(r):
            a = g.assets[r.source_id]
            target = g.products[product_id].name if r.target_type == "product" else vendor.name
            reach(a, r, f"asset '{a.name}' depends on {target}", 1)
        elif r.rel_type in ("HAS_ACCESS_TO", "CONNECTS_TO", "HOSTS") and r.target_type == "asset" and r.target_id in g.assets and (
            (r.source_type == "vendor" and r.source_id == vendor_id) or (r.source_type == "product" and r.source_id == product_id)
        ) and usable(r):
            a = g.assets[r.target_id]
            reach(a, r, f"{vendor.name} {r.rel_type.lower().replace('_', ' ')} asset '{a.name}'", 1, r.access_scope)
        elif r.rel_type == "MANAGES_FOR" and r.source_id == vendor_id and r.target_id in g.clients and usable(r):
            links[r.target_id]["relationships"].append(_rel(r, f"{vendor.name} manages services for {g.clients[r.target_id].name}", hop=0))

    # Bounded, cycle-safe walk to assets that depend on an already-affected asset.
    dependents: dict[uuid.UUID, list] = defaultdict(list)
    for r in sorted(g.rels, key=lambda x: str(x.id)):
        if r.rel_type == "DEPENDS_ON" and r.source_type == "asset" and r.target_type == "asset":
            dependents[r.target_id].append(r)
    while frontier:
        asset_id, hop = frontier.popleft()
        if hop >= max_depth:
            continue
        for r in dependents.get(asset_id, []):
            dep = g.assets.get(r.source_id)
            if dep is None or r.source_id in seen_assets or not usable(r):
                continue
            upstream = g.assets[asset_id]
            reach(dep, r, f"asset '{dep.name}' depends on asset '{upstream.name}' (affected, hop {hop + 1})", hop + 1)

    links = dict(links)
    for slot in links.values():
        slot["ignored_disputed"] = ignored["disputed"]
    return links


def _relationship_confidence(rels: list[dict], has_assets: bool) -> str:
    if not rels or not has_assets:
        return "low"  # vendor-level link only: the client uses the vendor, product use is unestablished
    verified = [r for r in rels if r["verification_status"] == "verified"]
    if len(verified) == len(rels):
        return "high"
    return "medium" if verified else "low"


# --------------------------------------------------------------------------- assessment content
def build_assessment(adv: Advisory, product: Product, vendor: Vendor, result, match_status: str, link: dict | None, client_count: int, *, exposure_status: str = "unverified") -> dict:
    """All engine-derived fields of one assessment, with every prioritisation factor spelled out."""
    assets = list((link or {}).get("assets", {}).values())
    rels = (link or {}).get("relationships", [])
    has_assets = bool(assets)
    rel_conf = _relationship_confidence(rels, has_assets)
    match_conf = {"cpe": "high", "name": "medium", "alias": "medium", "fuzzy": "low"}[result.match_type]
    source_conf = "high" if adv.source in ("nvd", "kev") or adv.known_exploited else "medium"
    impact_conf = "medium" if match_status == "matched" and has_assets and rel_conf in ("high", "medium") else "low"

    factors: list[dict] = []

    def factor(name, points, detail):
        factors.append({"factor": name, "points": points, "detail": detail})

    factor("Advisory severity", SEV_POINTS.get(adv.severity, 0), f"Severity '{adv.severity}'" + (f" (CVSS {adv.cvss_score}, source: {adv.source.upper()})" if adv.cvss_score is not None else f" (source: {adv.source.upper()})"))
    factor("Known exploitation", 3 if adv.known_exploited else 0, "Listed as exploited in the wild" if adv.known_exploited else "No exploitation reported in ingested sources")
    factor("Asset criticality", max((CRIT_POINTS.get(a.criticality, 1) for a in assets), default=0), f"{len(assets)} linked asset(s)" if assets else "No linked asset recorded")
    exposed = any(a.internet_exposed for a in assets)
    factor("Internet exposure", 1 if exposed else 0, "A linked asset is internet-exposed" if exposed else "No linked asset recorded as internet-exposed")
    factor("Vendor access", ACCESS_POINTS.get(vendor.access_level, 0), f"Vendor access level recorded as '{vendor.access_level}'")
    factor("Shared across clients", 1 if client_count >= 3 else 0, f"{client_count} client(s) linked to this vendor/product")
    factor("Match quality", MATCH_QUALITY[result.match_type], {"cpe": "Exact product identifier (CPE)", "name": "Vendor and product name", "alias": "Alias match", "fuzzy": "Ambiguous name — not a firm match"}[result.match_type])
    factor("Exposure verification", 2 if exposure_status == "verified" else 0, "An analyst verified the vulnerable exposure" if exposure_status == "verified" else "Exposure has not been verified")
    if match_status in ("insufficient_data", "needs_review"):
        factor("Evidence quality", -2, "Match or version cannot be confirmed from the inventory")
    elif rel_conf == "low":
        factor("Evidence quality", -1, "Relationships are unverified or only vendor-level")
    else:
        factor("Evidence quality", 0, "Relationships are verified")
    total = sum(f["points"] for f in factors)
    priority = "critical" if total >= 10 else "high" if total >= 7 else "medium" if total >= 4 else "low"

    unknowns = []
    if result.version_status == "unknown":
        unknowns.append("The deployed version is not recorded (or the advisory does not say which versions are affected), so it is unknown whether it is in the affected range.")
    if result.version_status == "unsupported":
        unknowns.append(f"The recorded version '{product.version}' cannot be interpreted safely for the '{product.ecosystem}' ecosystem; it was not guessed.")
    if result.match_type == "fuzzy":
        unknowns.append(f"Product identity is ambiguous: {result.detail}. An analyst must confirm it is the same product.")
    if not has_assets:
        unknowns.append("No asset-level relationship is recorded for this client, so which systems use the product is unknown.")
    if any(r["verification_status"] == "unverified" for r in rels):
        unknowns.append("Some relationships on the impact path are not verified.")
    if any(r["verification_status"] == "stale" for r in rels):
        unknowns.append("Some relationships on the path are marked stale and may no longer reflect the environment.")
    if link and link.get("ignored_disputed"):
        unknowns.append(f"{link['ignored_disputed']} disputed relationship(s) were ignored when tracing impact.")
    if any(r.get("hop", 1) > 1 for r in rels):
        unknowns.append("Some assets are affected only transitively (through another affected asset); direct use of the product is not recorded for them.")
    unknowns.append("Whether the vulnerable configuration is deployed and reachable has not been verified.")
    unknowns.append("Exploitation or compromise in this environment has not been established; an advisory match is not evidence of compromise.")

    steps = [f"Verify the deployed version of {product.name} against the affected range in {adv.advisory_id}."]
    if result.affected_range and result.affected_range.get("fixed_version"):
        steps.append(f"The advisory states {result.affected_range['fixed_version']} as the first unaffected version.")
    if adv.mitigation:
        steps.append("Review the vendor/source mitigation guidance and apply it where appropriate.")
    for a in assets:
        steps.append(f"Check '{a.name}' ({a.type}, {a.criticality} criticality) for the vulnerable configuration and review access logs.")
    if vendor.access_level in ("write", "admin"):
        steps.append(f"Review the permissions granted to {vendor.name} ({vendor.access_level}) and rotate credentials only if exposure is established and your response plan calls for it.")
    if not has_assets:
        steps.append("Record which client assets use this product so impact can be assessed.")
    steps.append("Document the result and update the inventory.")

    path = [
        {"step": "advisory", "label": f"{adv.advisory_id}: {adv.title}", "source": adv.source, "url": adv.source_url},
        {"step": "product", "label": f"{vendor.name} {product.name} {product.version or '(version not recorded)'}", "match": result.match_type, "version_status": result.version_status},
    ]
    for a in assets:
        path.append({"step": "asset", "label": f"{a.name} ({a.type}, {a.environment})", "criticality": a.criticality, "hop": (link or {}).get("hops", {}).get(a.id, 1)})

    evidence = {
        "advisory": {
            "id": adv.advisory_id, "title": adv.title, "severity": adv.severity, "cvss_score": adv.cvss_score,
            "known_exploited": adv.known_exploited, "source": adv.source, "source_url": adv.source_url,
            "published_at": adv.published_at.isoformat() if adv.published_at else None,
            "modified_at": adv.modified_at.isoformat() if adv.modified_at else None,
            "synthetic": adv.is_synthetic,
        },
        "match": {
            "type": result.match_type, "version_status": result.version_status, "detail": result.detail, "recorded_version": product.version,
            "ecosystem": product.ecosystem, "affected_range": result.affected_range or {}, "matcher_version": result.matcher_version,
        },
        "path": path,
        "relationships": rels,
        "assets": [{"id": str(a.id), "name": a.name, "criticality": a.criticality, "internet_exposed": a.internet_exposed} for a in assets],
        "known": [
            f"The advisory ({adv.source}) lists {result.detail or 'a matching product'} as affected.",
            f"The inventory records {vendor.name} {product.name} version '{product.version or 'unspecified'}' (match type: {result.match_type}).",
        ],
    }
    return {
        "match_status": match_status, "match_type": result.match_type, "version_status": result.version_status,
        "source_confidence": source_conf, "match_confidence": match_conf, "relationship_confidence": rel_conf, "impact_confidence": impact_conf,
        "priority": priority, "priority_factors": factors, "evidence": evidence, "unknowns": unknowns, "recommended_steps": steps,
        "path_relationship_ids": [r["id"] for r in rels], "matcher_version": result.matcher_version,
    }


def _add_event(db: Session, org_id, assessment_id, event_type, from_state="", to_state="", actor=None, note=""):
    db.add(AssessmentEvent(organization_id=org_id, assessment_id=assessment_id, event_type=event_type, from_state=from_state, to_state=to_state, actor_id=getattr(actor, "id", None), note=note))


def write_evidence(db: Session, org_id: uuid.UUID, assessment: ImpactAssessment, adv: Advisory, product: Product, vendor: Vendor, link: dict | None, result, *, source_record=None, new: bool = False) -> None:
    """Snapshot the inputs of a conclusion. Earlier rows are superseded, never edited, so reasoning outlives later changes."""
    now = utcnow()
    if not new:
        for old in db.scalars(select(AssessmentEvidence).where(AssessmentEvidence.assessment_id == assessment.id, AssessmentEvidence.superseded_at.is_(None), AssessmentEvidence.kind != "analyst_note")):
            old.superseded_at = now
    src = source_record
    if src is None and not new:
        src = db.scalar(select(SourceRecord).where(SourceRecord.external_id == adv.advisory_id).order_by(SourceRecord.retrieved_at.desc()))

    def add(kind, ref, summary, snapshot):
        db.add(AssessmentEvidence(organization_id=org_id, assessment_id=assessment.id, kind=kind, ref_id=str(ref), summary=summary, snapshot=snapshot))

    add("advisory", adv.id, f"{adv.advisory_id} ({adv.source}) severity {adv.severity}", {
        "advisory_id": adv.advisory_id, "source": adv.source, "source_url": adv.source_url, "severity": adv.severity, "cvss": adv.cvss_score,
        "known_exploited": adv.known_exploited, "published_at": adv.published_at.isoformat() if adv.published_at else None,
        "modified_at": adv.modified_at.isoformat() if adv.modified_at else None, "content_hash": adv.content_hash,
    })
    if src is not None:
        add("source_record", src.id, f"Original {src.source} record retrieved {src.retrieved_at.isoformat()}", {"source": src.source, "external_id": src.external_id, "content_hash": src.content_hash, "url": src.source_url, "retrieved_at": src.retrieved_at.isoformat()})
    add("product", product.id, f"{vendor.name} {product.name} {product.version or '(no version)'} matched by {result.match_type}", {
        "vendor": vendor.name, "product": product.name, "version": product.version, "cpe": product.cpe, "ecosystem": product.ecosystem,
        "match_type": result.match_type, "version_status": result.version_status, "affected_range": result.affected_range, "matcher_version": result.matcher_version,
    })
    for r in (link or {}).get("relationships", []):
        add("relationship", r["id"], r["label"], r)
    for a in (link or {}).get("assets", {}).values():
        add("asset", a.id, f"{a.name} ({a.type}, {a.criticality})", {"name": a.name, "type": a.type, "criticality": a.criticality, "environment": a.environment, "internet_exposed": a.internet_exposed})


# --------------------------------------------------------------------------- the run
def correlate_org(db: Session, org_id: uuid.UUID, advisory_ids: set[uuid.UUID] | None = None, *, actor=None) -> CorrelationRun:
    """Evaluate the organization's inventory against advisories and upsert matches and assessments.

    db must be scoped to org_id (row-level security). Safe to re-run: results are upserted per
    (advisory, product) / (advisory, product, client) and things that no longer match are marked `no_match`."""
    run = CorrelationRun(organization_id=org_id)
    db.add(run)
    db.flush()
    try:
        g = gsvc.load_graph(db, org_id)
        inventory = [(p, g.vendors[p.vendor_id]) for p in g.products.values() if p.vendor_id in g.vendors]
        vendor_keys: set[str] = set()
        for p, v in inventory:
            vendor_keys |= inventory_keys(_inventory(p, v))[0]

        candidates: dict[uuid.UUID, list[AffectedProduct]] = defaultdict(list)
        if vendor_keys:
            q = select(AffectedProduct).where(AffectedProduct.vendor_norm.in_(vendor_keys), AffectedProduct.vulnerable.is_(True))
            if advisory_ids is not None:
                q = q.where(AffectedProduct.advisory_id.in_(advisory_ids))
            for ap in db.scalars(q):
                candidates[ap.advisory_id].append(ap)

        advisories = {a.id: a for a in db.scalars(select(Advisory).where(Advisory.id.in_(candidates.keys())))} if candidates else {}
        run.advisories_considered = len(advisories)
        client_counts = {v.id: len({r.source_id for r in g.rels if r.rel_type == "USES_VENDOR" and r.target_id == v.id}) for v in g.vendors.values()}

        match_q = select(AdvisoryMatch).where(AdvisoryMatch.organization_id == org_id)
        if advisory_ids is not None:
            match_q = match_q.where(AdvisoryMatch.advisory_id.in_(advisory_ids))
        existing_matches = {(m.advisory_id, m.product_id): m for m in db.scalars(match_q)}

        existing_assessments = {
            (a.advisory_id, a.product_id, a.client_id): a
            for a in db.scalars(
                select(ImpactAssessment).where(ImpactAssessment.organization_id == org_id, *( [ImpactAssessment.advisory_id.in_(advisory_ids)] if advisory_ids is not None else [] ))
            )
        }
        source_records = {}
        if advisories:
            for rec in db.scalars(select(SourceRecord).where(SourceRecord.external_id.in_([a.advisory_id for a in advisories.values()])).order_by(SourceRecord.retrieved_at)):
                source_records[rec.external_id] = rec  # the newest retrieval wins
        links_cache: dict[uuid.UUID, dict] = {}  # relationship chains depend on the product, not on the advisory
        deferred: list = []
        produced_matches: set[tuple] = set()
        produced: set[tuple] = set()
        for adv_pk, aps in candidates.items():
            adv = advisories.get(adv_pk)
            if adv is None:
                continue
            specs = [_spec(ap) for ap in aps]
            for product, vendor in inventory:
                result = best_match(_inventory(product, vendor), specs)
                key = (adv.id, product.id)
                match = existing_matches.get(key)
                if result.status == "no_match":
                    continue  # stale handling below marks any previous match
                if match is not None and match.status == "incorrect":
                    produced_matches.add(key)
                    continue  # an analyst declared this match wrong; it is not silently resurrected
                fields = {
                    "method": result.match_type, "matcher_version": result.matcher_version, "observed_version": product.version,
                    "affected_range": result.affected_range or {}, "version_status": result.version_status, "status": result.status,
                    "evidence": {"detail": result.detail, "advisory": adv.advisory_id, "source": adv.source, "ecosystem": product.ecosystem},
                    "vendor_id": vendor.id,
                }
                if match is None:
                    match = AdvisoryMatch(id=uuid.uuid4(), organization_id=org_id, advisory_id=adv.id, product_id=product.id, **fields)
                    db.add(match)
                    db.flush()  # the match must exist before assessments reference it (no ORM relationship() orders inserts for us)
                else:
                    for k, v in fields.items():
                        setattr(match, k, v)
                produced_matches.add(key)

                if product.id not in links_cache:
                    links_cache[product.id] = client_links(g, vendor.id, product.id)
                links = links_cache[product.id]
                targets = links.items() if links else [(None, None)]
                for client_id, link in targets:
                    produced.add((adv.id, product.id, client_id))
                    fields_a = build_assessment(adv, product, vendor, result, ASSESSMENT_MATCH_STATUS[result.status], link, max(client_counts.get(vendor.id, 0), len(links)))
                    fields_a["advisory_hash"] = adv.content_hash
                    if client_id is None:
                        fields_a["unknowns"].insert(0, "No client is linked to this product in the recorded graph.")
                    _upsert_assessment(db, org_id, run, adv, product, vendor, client_id, fields_a, match, link, result, existing_assessments, source_records.get(adv.advisory_id), deferred)
                # Child rows (evidence, events) are written after the parents are flushed: one flush per match, not per assessment.
                db.flush()
                for write_children in deferred:
                    write_children()
                deferred.clear()

        # Matches and assessments that no longer hold (inventory or advisory changed).
        for key, match in existing_matches.items():
            if key not in produced_matches and match.status not in ("incorrect", "no_match"):
                match.status = "no_match"
        scope = select(ImpactAssessment).where(ImpactAssessment.organization_id == org_id, ImpactAssessment.match_status != "no_match")
        if advisory_ids is not None:
            scope = scope.where(ImpactAssessment.advisory_id.in_(advisory_ids))
        for existing in db.scalars(scope):
            if (existing.advisory_id, existing.product_id, existing.client_id) not in produced and existing.review_status != "dismissed":
                before = existing.state
                existing.match_status = "no_match"
                existing.state = derive_state(existing)
                existing.review_status = "unreviewed"
                existing.last_evaluated_at = utcnow()
                _add_event(db, org_id, existing.id, "state_changed", before, existing.state, None, "No longer matches after an inventory or advisory change.")
                run.assessments_updated += 1

        run.status = "succeeded"
    except Exception as exc:  # recorded so failed correlation is visible, then re-raised
        db.rollback()
        run = CorrelationRun(organization_id=org_id, status="failed", error=str(exc)[:2000], finished_at=utcnow())
        db.add(run)
        db.commit()
        raise
    run.finished_at = utcnow()
    audit.record(db, org_id, "correlation.completed", actor=actor, object_type="correlation_run", object_id=run.id,
                 metadata={"created": run.assessments_created, "updated": run.assessments_updated, "advisories": run.advisories_considered, "matcher_version": MATCHER_VERSION})
    db.commit()
    return run


def _upsert_assessment(db, org_id, run, adv, product, vendor, client_id, fields, match, link, result, existing_map, source_record, deferred):
    existing = existing_map.get((adv.id, product.id, client_id))
    if existing is None:
        a = ImpactAssessment(id=uuid.uuid4(), organization_id=org_id, advisory_id=adv.id, product_id=product.id, vendor_id=vendor.id, client_id=client_id, match_id=match.id, state="potential_impact", **fields)
        db.add(a)
        a.state = derive_state(a)
        existing_map[(adv.id, product.id, client_id)] = a
        deferred.append(
            lambda a=a: (
                write_evidence(db, org_id, a, adv, product, vendor, link, result, source_record=source_record, new=True),
                _add_event(db, org_id, a.id, "created", "", a.state, None, f"Created from {adv.advisory_id} by deterministic matching ({a.match_type}, matcher {a.matcher_version})."),
            )
        )
        run.assessments_created += 1
        return
    previous_state, previous_hash = existing.state, existing.advisory_hash
    # Recompute exposure-dependent priority points using the analyst's current exposure decision.
    if existing.exposure_status == "verified":
        fields = {**fields, **_with_exposure(fields)}
    changed = (
        previous_hash != fields["advisory_hash"]
        or existing.evidence != fields["evidence"]
        or existing.priority != fields["priority"]
        or existing.match_status != fields["match_status"]
        or existing.match_id != match.id
    )
    existing.last_evaluated_at = utcnow()
    if not changed:
        return
    for key, value in fields.items():
        setattr(existing, key, value)
    existing.match_id = match.id
    existing.state = derive_state(existing)  # analyst-set exposure/compromise/dependency survive; only match status moved
    write_evidence(db, org_id, existing, adv, product, vendor, link, result, source_record=source_record)
    if previous_hash != fields["advisory_hash"]:
        existing.review_status = "unreviewed"
        _add_event(db, org_id, existing.id, "advisory_changed", previous_state, existing.state, None, "The advisory changed upstream; this assessment was recalculated and needs re-review.")
    elif previous_state != existing.state:
        _add_event(db, org_id, existing.id, "state_changed", previous_state, existing.state, None, "Recalculated after an inventory change.")
    else:
        _add_event(db, org_id, existing.id, "recalculated", previous_state, existing.state, None, "Evidence or priority recalculated after an inventory change.")
    run.assessments_updated += 1


def priority_label(total: int) -> str:
    return "critical" if total >= 10 else "high" if total >= 7 else "medium" if total >= 4 else "low"


def rescore_exposure(factors: list[dict], exposure_status: str) -> tuple[list[dict], str]:
    """Re-score the 'Exposure verification' factor after an analyst changes the exposure decision."""
    out = [dict(f) for f in factors]
    for f in out:
        if f["factor"] == "Exposure verification":
            verified = exposure_status == "verified"
            f.update(points=2 if verified else 0, detail="An analyst verified the vulnerable exposure" if verified else "Exposure has not been verified")
    return out, priority_label(sum(f["points"] for f in out))


def _with_exposure(fields: dict) -> dict:
    factors, priority = rescore_exposure(fields["priority_factors"], "verified")
    return {"priority_factors": factors, "priority": priority}


def correlate_all_orgs(db_factory, advisory_ids: set[uuid.UUID] | None = None) -> int:
    """Used by background jobs after ingestion: one tenant-scoped session per organization."""
    from ..db import org_session

    with db_factory() as db:
        org_ids = list(db.scalars(select(Organization.id)))
    for org_id in org_ids:
        with org_session(org_id) as scoped:
            correlate_org(scoped, org_id, advisory_ids)
    return len(org_ids)
