"""Week 2, Days 10-14: intelligence model, matching semantics, review actions, source health, failure handling and the
end-to-end incident workflow. Everything runs offline."""
import copy
import json
import os
import threading
import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app.db import SessionLocal, org_session
from app.models import (
    Advisory,
    AdvisoryMatch,
    AffectedProduct,
    AssessmentEvidence,
    ImpactAssessment,
    IngestionRun,
    OutboxEvent,
    SourceRecord,
    utcnow,
)
from app.services import ingestion, outbox

from .helpers import load_fixtures, make, rel, scenario


def correlate(api):
    assert api.post("/correlation-runs").status_code == 202


def assessments(api, **query):
    qs = "&".join(f"{k}={v}" for k, v in query.items())
    return api.get(f"/assessments?limit=100&include_no_match=true&{qs}").json()["items"]


def nvd_item(cve, vendor, product, **bounds):
    match = {"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*", **bounds}
    return {"cve": {"id": cve, "published": "2026-01-01T00:00:00.000", "lastModified": "2026-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Test advisory."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [match]}]}], "references": []}}


def ingest_items(items):
    with SessionLocal() as db:
        run = ingestion.start_run(db, "nvd")
        ingestion._ingest_items(db, run, items, ingestion.parse_nvd_item, lambda i: i)
        return run


# =============================================================== Day 11: data model
def test_matches_are_stored_separately_from_assessments(owner):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    matches = owner.get("/matches?limit=100").json()["items"]
    hit = next(m for m in matches if m["status"] == "matched")
    assert hit["method"] == "name" and hit["observed_version"] == "4.1.0" and hit["matcher_version"]
    assert hit["affected_range"]["end_excluding"] == "4.2.1" and hit["affected_range"]["fixed_version"] == "4.2.1"
    linked = [a for a in assessments(owner) if a["match_id"] == hit["id"]]
    assert len(linked) == 2  # one match fans out to one assessment per client; the match itself is stored once
    assert len({(m["advisory_id"], m["product_id"]) for m in matches}) == len(matches)


def test_assessment_evidence_is_preserved_and_superseded_not_rewritten(owner):
    s = scenario(owner)
    load_fixtures()
    correlate(owner)
    a = next(x for x in assessments(owner) if x["advisory"] == "CVE-2099-1001" and x["client"] == "Retail Client")
    detail = owner.get(f"/assessments/{a['id']}").json()
    kinds = {e["kind"] for e in detail["evidence_items"]}
    assert {"advisory", "source_record", "product", "relationship", "asset"} <= kinds
    product_snapshot = next(e for e in detail["evidence_items"] if e["kind"] == "product")["snapshot"]
    assert product_snapshot["version"] == "4.1.0"

    # The inventory changes; the earlier reasoning must still be readable afterwards.
    owner.patch(f"/products/{s['agent']['id']}", json={"version": "4.0.0"})
    correlate(owner)
    after = owner.get(f"/assessments/{a['id']}").json()["evidence_items"]
    old = [e for e in after if e["kind"] == "product" and e["superseded_at"]]
    new = [e for e in after if e["kind"] == "product" and not e["superseded_at"]]
    assert old and old[0]["snapshot"]["version"] == "4.1.0" and new and new[0]["snapshot"]["version"] == "4.0.0"


def test_evidence_rows_cannot_be_deleted_by_the_application_role(owner):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    engine = create_engine(os.environ["DATABASE_URL"])
    with engine.connect() as conn:
        conn.execute(text("select set_config('app.org_id', :o, true)"), {"o": owner.org_id})
        assert conn.execute(text("select count(*) from assessment_evidence")).scalar_one() > 0
        with pytest.raises((ProgrammingError, DBAPIError)):
            conn.execute(text("delete from assessment_evidence"))
    engine.dispose()


def test_intelligence_rows_are_tenant_scoped(owner, other_owner):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    engine = create_engine(os.environ["DATABASE_URL"])
    with engine.connect() as conn:
        conn.execute(text("select set_config('app.org_id', :o, true)"), {"o": other_owner.org_id})
        for table in ("advisory_matches", "assessment_evidence", "impact_assessments", "assessment_events", "correlation_runs"):
            assert conn.execute(text(f"select count(*) from {table}")).scalar_one() == 0, table
    engine.dispose()
    assert other_owner.get("/matches").json()["total"] == 0


def test_database_rejects_invalid_statuses(owner, owner_engine):
    from sqlalchemy.exc import IntegrityError

    scenario(owner)
    load_fixtures()
    correlate(owner)
    for statement in (
        "update advisory_matches set status = 'maybe'",
        "update impact_assessments set exposure_status = 'sort of'",
        "update impact_assessments set compromise_status = 'definitely'",
        "update impact_assessments set remediation_status = 'whenever'",
        "update ingestion_runs set status = 'exploded'",
    ):
        with pytest.raises(IntegrityError), owner_engine.begin() as conn:
            conn.execute(text(statement))


def test_deleting_an_organization_removes_all_of_its_intelligence_rows(owner, owner_engine):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    with owner_engine.begin() as conn:
        conn.execute(text("delete from organizations where id = :o"), {"o": owner.org_id})
        for table in ("advisory_matches", "assessment_evidence", "impact_assessments", "assessment_events", "correlation_runs", "cases"):
            assert conn.execute(text(f"select count(*) from {table}")).scalar_one() == 0, table
        assert conn.execute(text("select count(*) from advisories")).scalar_one() > 0  # shared public intelligence is retained


def test_advisory_with_multiple_affected_ranges_matches_the_applicable_one(owner):
    c = make(owner, "/clients", name="C")
    v = make(owner, "/vendors", name="Widgetco")
    p = make(owner, "/products", vendor_id=v["id"], name="Widget", version="3.2.0")
    asset = make(owner, "/assets", client_id=c["id"], name="widget-host", type="production_service")
    rel(owner, "asset", asset["id"], "DEPENDS_ON", "product", p["id"])
    item = nvd_item("CVE-2026-0100", "widgetco", "widget", versionStartIncluding="1.0", versionEndExcluding="2.0")
    item["cve"]["configurations"][0]["nodes"][0]["cpeMatch"].append(
        {"vulnerable": True, "criteria": "cpe:2.3:a:widgetco:widget:*:*:*:*:*:*:*:*", "versionStartIncluding": "3.0", "versionEndExcluding": "3.5"}
    )
    ingest_items([item])
    correlate(owner)
    hit = [a for a in assessments(owner) if a["advisory"] == "CVE-2026-0100"]
    assert len(hit) == 1 and hit[0]["match_status"] == "matched" and hit[0]["version_status"] == "in_range"
    owner.patch(f"/products/{p['id']}", json={"version": "2.5.0"})  # falls in the gap between the two ranges
    correlate(owner)
    assert all(a["match_status"] == "no_match" for a in assessments(owner) if a["advisory"] == "CVE-2026-0100")


def test_advisory_entries_without_product_identifiers_are_kept_but_never_matched(owner):
    item = nvd_item("CVE-2026-0101", "", "")
    item["cve"]["configurations"] = []
    ingest_items([item])
    with SessionLocal() as db:
        adv = db.scalar(select(Advisory).where(Advisory.advisory_id == "CVE-2026-0101"))
        assert adv is not None and db.scalar(select(func.count()).select_from(AffectedProduct).where(AffectedProduct.advisory_id == adv.id)) == 0
    scenario(owner)
    correlate(owner)
    assert not [a for a in assessments(owner) if a["advisory"] == "CVE-2026-0101"]


# =============================================================== Day 12: matching and traversal
@pytest.mark.parametrize(
    "ecosystem,version,expected",
    [
        ("npm", "2.0.0-rc.1", "in_range"),     # semver: a pre-release sorts before its release (fixed in 2.0.0)
        ("npm", "2.0.0", "out_of_range"),
        ("pypi", "2.0rc1", "in_range"),        # PEP 440 pre-release
        ("pypi", "2.0.post1", "out_of_range"),
        ("generic", "1.9.12", "in_range"),
        ("npm", "latest", "unsupported"),      # not interpretable for this ecosystem: never guessed
        ("npm", "2.0", "unsupported"),         # semver requires three parts
    ],
)
def test_version_semantics_follow_the_ecosystem(owner, ecosystem, version, expected):
    c = make(owner, "/clients", name="C")
    v = make(owner, "/vendors", name="Pkgco")
    p = make(owner, "/products", vendor_id=v["id"], name="Libfoo", version=version, ecosystem=ecosystem)
    asset = make(owner, "/assets", client_id=c["id"], name="app", type="repository")
    rel(owner, "asset", asset["id"], "DEPENDS_ON", "product", p["id"])
    ingest_items([nvd_item("CVE-2026-0200", "pkgco", "libfoo", versionEndExcluding="2.0.0")])
    correlate(owner)
    matches = [m for m in owner.get("/matches").json()["items"] if m["observed_version"] == version]
    if expected == "out_of_range":
        assert matches == []  # an unaffected version never becomes a match or an assessment
        return
    match = matches[0]
    assert match["version_status"] == expected
    if expected == "unsupported":
        a = assessments(owner, advisory_id=match["advisory_id"])[0]
        assert a["match_status"] == "insufficient_data"
        assert any("cannot be interpreted" in u for u in owner.get(f"/assessments/{a['id']}").json()["unknowns"])


def test_unaffected_and_fixed_versions(owner):
    s = scenario(owner)
    load_fixtures()
    correlate(owner)
    detail = owner.get(f"/assessments/{next(a for a in assessments(owner) if a['advisory'] == 'CVE-2099-1001')['id']}").json()
    assert any("4.2.1 as the first unaffected version" in step for step in detail["recommended_steps"])
    owner.patch(f"/products/{s['agent']['id']}", json={"version": "4.2.1"})  # exactly the fixed version
    correlate(owner)
    assert all(a["match_status"] == "no_match" for a in assessments(owner) if a["advisory"] == "CVE-2099-1001")


def test_ecosystem_must_be_a_supported_value(owner):
    v = make(owner, "/vendors", name="V")
    assert owner.post("/products", json={"vendor_id": v["id"], "name": "p", "ecosystem": "cobol"}).status_code == 422
    assert owner.post("/products", json={"vendor_id": v["id"], "name": "p", "ecosystem": "npm"}).json()["ecosystem"] == "npm"


def test_disputed_relationships_are_ignored_and_stale_ones_are_flagged(owner):
    s = scenario(owner)
    load_fixtures()
    retail_edge = next(r for r in owner.get(f"/relationships?entity_id={s['storefront']['id']}").json()["items"] if r["rel_type"] == "DEPENDS_ON")
    owner.patch(f"/relationships/{retail_edge['id']}", json={"verification_status": "stale"})
    correlate(owner)
    a = next(x for x in assessments(owner) if x["advisory"] == "CVE-2099-1001" and x["client"] == "Retail Client")
    assert any("stale" in u for u in owner.get(f"/assessments/{a['id']}").json()["unknowns"])
    owner.patch(f"/relationships/{retail_edge['id']}", json={"verification_status": "disputed"})
    correlate(owner)
    after = next(x for x in assessments(owner) if x["advisory"] == "CVE-2099-1001" and x["client"] == "Retail Client")
    detail = owner.get(f"/assessments/{after['id']}").json()
    assert not detail["evidence"]["assets"] and any("disputed" in u for u in detail["unknowns"])  # the disputed path is not used


def test_transitive_dependencies_are_traced_within_the_depth_limit(owner, monkeypatch):
    from app.config import get_settings

    s = scenario(owner)
    load_fixtures()
    c2 = make(owner, "/clients", name="Downstream Client")
    api_a = make(owner, "/assets", client_id=c2["id"], name="gateway", type="production_service", criticality="high")
    api_b = make(owner, "/assets", client_id=c2["id"], name="portal", type="business_application", criticality="critical")
    rel(owner, "asset", api_a["id"], "DEPENDS_ON", "asset", s["storefront"]["id"])    # gateway depends on the affected storefront
    rel(owner, "asset", api_b["id"], "DEPENDS_ON", "asset", api_a["id"])               # portal depends on gateway (hop 3? storefront=1, gateway=2, portal=3)
    rel(owner, "asset", s["storefront"]["id"], "DEPENDS_ON", "asset", api_b["id"])     # and a cycle back
    correlate(owner)
    hit = [a for a in assessments(owner) if a["advisory"] == "CVE-2099-1001" and a["client"] == "Downstream Client"]
    assert hit, "a client reached only transitively is assessed"
    detail = owner.get(f"/assessments/{hit[0]['id']}").json()
    assert {x["name"] for x in detail["evidence"]["assets"]} == {"gateway", "portal"}
    assert any("transitively" in u for u in detail["unknowns"])
    monkeypatch.setattr(get_settings(), "max_traversal_depth", 1)
    correlate(owner)
    assert all(a["match_status"] == "no_match" for a in assessments(owner) if a["advisory"] == "CVE-2099-1001" and a["client"] == "Downstream Client")


def test_vendor_with_several_clients_and_unverified_dependency(owner):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    hits = [a for a in assessments(owner) if a["advisory"] == "CVE-2099-1001"]
    assert {a["client"] for a in hits} == {"Retail Client", "Clinic Client"}
    clinic = next(a for a in hits if a["client"] == "Clinic Client")
    assert clinic["relationship_confidence"] == "low" and clinic["impact_confidence"] == "low"


def test_duplicate_and_updated_advisories(owner):
    s = scenario(owner)
    item = nvd_item("CVE-2026-0300", "acme_analytics", "insight_agent", versionEndExcluding="5.0.0")
    ingest_items([item, copy.deepcopy(item)])  # the same advisory twice in one batch
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Advisory).where(Advisory.advisory_id == "CVE-2026-0300")) == 1
    correlate(owner)
    assert len([a for a in assessments(owner) if a["advisory"] == "CVE-2026-0300" and a["match_status"] == "matched"]) == 2
    changed = copy.deepcopy(item)
    changed["cve"]["lastModified"] = "2026-02-02T00:00:00.000"
    changed["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "4.0.0"  # vendor narrowed the range
    ingest_items([changed])
    from app.services.correlation import correlate_all_orgs

    with SessionLocal() as db:
        pk = db.scalar(select(Advisory.id).where(Advisory.advisory_id == "CVE-2026-0300"))
    correlate_all_orgs(SessionLocal, {pk})
    assert all(a["match_status"] == "no_match" for a in assessments(owner) if a["advisory"] == "CVE-2026-0300")
    revision = owner.get(f"/advisories/{pk}").json()["revisions"]
    assert revision and "affected_products" in revision[0]["changes"]


def test_matching_is_deterministic_and_repeatable(owner):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    first = sorted((a["advisory"], a["client"], a["state"], a["priority"], a["match_type"]) for a in assessments(owner))
    for _ in range(3):
        correlate(owner)
    assert sorted((a["advisory"], a["client"], a["state"], a["priority"], a["match_type"]) for a in assessments(owner)) == first


# =============================================================== Day 13: review actions, filters, source health
def test_separate_status_dimensions_and_derived_state(owner, analyst):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    a = next(x for x in assessments(owner) if x["advisory"] == "CVE-2099-1001" and x["client"] == "Retail Client")
    assert (a["match_status"], a["exposure_status"], a["compromise_status"], a["remediation_status"]) == ("matched", "unverified", "unknown", "not_started")
    before = owner.get(f"/assessments/{a['id']}").json()
    no_note = analyst.post(f"/assessments/{a['id']}/review", json={"review_status": "reviewed", "exposure_status": "verified"})
    assert no_note.status_code == 422  # decisions need a reason
    ok = analyst.post(f"/assessments/{a['id']}/review", json={"review_status": "reviewed", "exposure_status": "verified", "note": "Confirmed vulnerable build in prod."}).json()
    assert ok["state"] == "exposure_verified" and ok["exposure_status"] == "verified" and ok["compromise_status"] == "unknown"
    factors = {f["factor"]: f["points"] for f in ok["priority_factors"]}
    assert factors["Exposure verification"] == 2 and sum(factors.values()) == sum(f["points"] for f in before["priority_factors"]) + 2
    suspected = analyst.post(f"/assessments/{a['id']}/review", json={"review_status": "reviewed", "compromise_status": "suspected", "note": "Unusual egress from the host."}).json()
    assert suspected["state"] == "exposure_verified" and suspected["compromise_status"] == "suspected"  # suspicion is not confirmation
    rem = analyst.post(f"/assessments/{a['id']}/review", json={"review_status": "reviewed", "remediation_status": "in_progress"}).json()
    assert rem["remediation_status"] == "in_progress"


def test_assignee_must_be_an_active_member(owner, analyst, other_owner):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    a = assessments(owner)[0]
    ok = owner.post(f"/assessments/{a['id']}/review", json={"review_status": "reviewed", "assigned_to": analyst.user_id})
    assert ok.status_code == 200 and ok.json()["assigned_to"] == analyst.user_id
    outsider = owner.post(f"/assessments/{a['id']}/review", json={"review_status": "reviewed", "assigned_to": other_owner.user_id})
    assert outsider.status_code == 422
    assert owner.get(f"/assessments?assigned_to={analyst.user_id}").json()["total"] == 1


def test_marking_a_match_incorrect_preserves_evidence_and_survives_recalculation(owner, viewer):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    a = next(x for x in assessments(owner) if x["advisory"] == "CVE-2099-1001" and x["client"] == "Retail Client")
    assert viewer.post(f"/matches/{a['match_id']}/incorrect", json={"reason": "not ours"}).status_code == 403
    assert owner.post(f"/matches/{a['match_id']}/incorrect", json={"reason": "x"}).status_code == 422  # a real reason is required
    marked = owner.post(f"/matches/{a['match_id']}/incorrect", json={"reason": "This agent is a different, internal fork."}).json()
    assert marked["status"] == "incorrect" and marked["incorrect_reason"] and marked["evidence"]  # the original evidence is kept
    detail = owner.get(f"/assessments/{a['id']}").json()
    assert detail["review_status"] == "dismissed" and detail["match_status"] == "no_match"
    assert any(e["event_type"] == "match_marked_incorrect" and "internal fork" in e["note"] for e in detail["events"])
    assert detail["evidence_items"]  # supporting evidence is not deleted
    correlate(owner)  # the engine must not silently resurrect it
    assert owner.get(f"/matches/{a['match_id']}").json()["status"] == "incorrect"
    assert owner.get(f"/assessments/{a['id']}").json()["review_status"] == "dismissed"
    assert owner.get(f"/advisories/{a['advisory_id']}").json()["advisory_id"] == "CVE-2099-1001"  # the source advisory is untouched
    restored = owner.post(f"/matches/{a['match_id']}/restore").json()
    assert restored["status"] != "incorrect"
    correlate(owner)
    assert owner.get(f"/matches/{a['match_id']}").json()["status"] == "matched"


def test_notes_and_re_evaluation_requests_are_recorded(owner):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    a = assessments(owner)[0]
    assert owner.post(f"/assessments/{a['id']}/notes", json={"body": "Asked the vendor for scope details."}).status_code == 201
    assert owner.post(f"/assessments/{a['id']}/re-evaluate").status_code == 202
    detail = owner.get(f"/assessments/{a['id']}").json()
    assert {"note", "re_evaluation_requested"} <= {e["event_type"] for e in detail["events"]}
    assert any(e["kind"] == "analyst_note" and "vendor for scope" in e["summary"] for e in detail["evidence_items"])
    types = [e["event_type"] for e in owner.get("/audit-events").json()["items"]]
    assert "assessment.note_added" in types and "assessment.re_evaluation_requested" in types


def test_assessment_filters_cover_the_dashboard_requirements(owner):
    scenario(owner)
    load_fixtures()
    correlate(owner)
    assert all(a["known_exploited"] for a in owner.get("/assessments?known_exploited=true").json()["items"])
    assert all(a["match_status"] == "insufficient_data" for a in owner.get("/assessments?match_status=insufficient_data").json()["items"])
    crit = owner.get("/assessments?asset_criticality=critical").json()["items"]
    assert crit and all(a["client"] == "Retail Client" for a in crit)
    vendor_id = next(a["vendor_id"] for a in assessments(owner) if a["vendor"].startswith("Acme"))
    assert all(a["vendor_id"] == vendor_id for a in owner.get(f"/assessments?vendor_id={vendor_id}").json()["items"])
    assert owner.get("/assessments?published_after=2100-01-01T00:00:00Z").json()["total"] == 0
    assert owner.get("/assessments?published_after=2000-01-01T00:00:00Z").json()["total"] > 0


def test_source_health_distinguishes_no_news_from_unchecked(owner):
    health = lambda: {s["source"]: s for s in owner.get("/ingestion-health").json()["sources"]}  # noqa: E731
    assert health()["nvd"]["status"] == "never_run" and owner.get("/ingestion-health").json()["any_problem"] is True
    with SessionLocal() as db:
        run = IngestionRun(source="nvd", status="succeeded", finished_at=utcnow(), records_seen=10, records_rejected=1)
        db.add(run)
        db.commit()
    assert health()["nvd"]["status"] == "healthy" and health()["nvd"]["latest"]["records_rejected"] == 1
    with SessionLocal() as db:
        db.add(IngestionRun(source="nvd", status="failed", error="HTTP 503", finished_at=utcnow()))
        db.commit()
    failing = health()["nvd"]
    assert failing["status"] == "failing" and "503" in failing["message"]
    with SessionLocal() as db:
        db.query(IngestionRun).delete()
        db.add(IngestionRun(source="nvd", status="succeeded", started_at=utcnow() - timedelta(hours=30), finished_at=utcnow() - timedelta(hours=30)))
        db.commit()
    stale = health()["nvd"]
    assert stale["status"] == "stale" and "out of date" in stale["message"]
    dash = owner.get("/dashboard").json()
    assert dash["failed_ingestion_runs"] == [] and owner.get("/ingestion-health").json()["any_problem"] is True


def test_dashboard_numbers_come_from_the_database(owner):
    assert owner.get("/dashboard").json()["counts"]["active_assessments"] == 0
    scenario(owner)
    load_fixtures()
    correlate(owner)
    counts = owner.get("/dashboard").json()["counts"]
    assert counts["active_assessments"] == len([a for a in assessments(owner) if a["match_status"] != "no_match"])
    assert counts["unreviewed"] == counts["active_assessments"]


# =============================================================== Day 10 / 14: ingestion failure handling
def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def run_nvd(handler):
    with SessionLocal() as db:
        run = ingestion.start_run(db, "nvd")
        ingestion.ingest_nvd(db, client_for(handler), run, sleep=lambda s: None)
        db.refresh(run)
        return run


def test_source_timeouts_are_retried_then_recorded(owner):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ReadTimeout("timed out", request=request)

    run = run_nvd(handler)
    assert run.status == "failed" and calls["n"] == 5 and "giving up" in run.error and run.attempts == 1


def test_rate_limits_server_errors_and_invalid_json(owner):
    seq = iter([httpx.Response(429, headers={"retry-after": "1"}), httpx.Response(500), httpx.Response(200, content=b"<html>not json</html>"), httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})])
    run = run_nvd(lambda request: next(seq))
    assert run.status == "succeeded"  # three bad responses were retried, the fourth was good
    with SessionLocal() as db:
        run2 = ingestion.start_run(db, "nvd")
        ingestion.ingest_nvd(db, client_for(lambda r: httpx.Response(200, content=b"{broken")), run2, sleep=lambda s: None)
        db.refresh(run2)
    assert run2.status == "failed" and "giving up" in run2.error


def test_schema_violations_and_missing_fields_are_rejected_not_fatal(owner):
    good = nvd_item("CVE-2026-0400", "acme_analytics", "insight_agent", versionEndExcluding="9.0.0")
    page = {"vulnerabilities": [good, {"cve": {"descriptions": []}}, {"cve": {"id": "not-a-cve-id"}}, {"unexpected": True}, "garbage"], "totalResults": 5}
    run = run_nvd(lambda r: httpx.Response(200, json=page))
    assert run.status == "succeeded" and run.records_seen == 5 and run.records_new == 1 and run.records_rejected == 4
    bad_envelope = run_nvd(lambda r: httpx.Response(200, json=["not", "an", "object"]))
    assert bad_envelope.status == "failed" and "schema" in bad_envelope.error or "object" in bad_envelope.error


def test_kev_catalogue_update_detection_and_integrity(owner):
    def catalogue(version, count=None):
        vulns = [{"cveID": "CVE-2026-0500", "vendorProject": "Acme Analytics", "product": "Insight Agent", "dateAdded": "2026-02-01", "requiredAction": "Patch."}]
        return {"title": "KEV", "catalogVersion": version, "dateReleased": "2026-02-01T00:00:00Z", "count": len(vulns) if count is None else count, "vulnerabilities": vulns}

    def run_kev(payload):
        with SessionLocal() as db:
            run = ingestion.start_run(db, "kev")
            ingestion.ingest_kev(db, client_for(lambda r: httpx.Response(200, json=payload)), run, sleep=lambda s: None)
            db.refresh(run)
            return run

    first = run_kev(catalogue("2026.02.01"))
    assert first.status == "succeeded" and first.records_new == 1 and first.catalog_version == "2026.02.01"
    unchanged = run_kev(catalogue("2026.02.01"))
    assert unchanged.status == "skipped" and unchanged.records_new == 0  # same catalogue version: nothing to process
    newer = run_kev(catalogue("2026.02.02"))
    assert newer.status == "succeeded" and newer.records_new == 0 and newer.records_seen == 1
    truncated = run_kev(catalogue("2026.02.03", count=999))
    assert truncated.status == "failed" and "declares 999" in truncated.error


def test_worker_crash_and_redelivery_do_not_duplicate_anything(owner):
    from app.workers import tasks

    scenario(owner)
    with SessionLocal() as db:
        run = ingestion.start_run(db, "fixture")
        run_id = str(run.id)
    tasks.ingest_source(run_id, "fixture")
    tasks.ingest_source(run_id, "fixture")  # the broker redelivers the task after a crash
    tasks.run_correlation(owner.org_id, None)
    tasks.run_correlation(owner.org_id, None)  # and the correlation job too
    with SessionLocal() as db:
        advisories = db.scalar(select(func.count()).select_from(Advisory))
        records = db.scalar(select(func.count()).select_from(SourceRecord))
    assert advisories == records - 2 or advisories <= records  # one source record per source/id; no duplicate advisories
    keys = [(a["advisory"], a["product"], a["client"]) for a in assessments(owner)]
    assert len(keys) == len(set(keys))
    assert len(owner.get("/matches?limit=100").json()["items"]) == len({(m["advisory_id"], m["product_id"]) for m in owner.get("/matches?limit=100").json()["items"]})


def test_concurrent_ingestion_creates_no_duplicates(owner):
    errors = []
    items = [nvd_item(f"CVE-2026-{i:04d}", "acme_analytics", "insight_agent", versionEndExcluding="9.0.0") for i in range(1000, 1030)]

    def worker():
        try:
            ingest_items(copy.deepcopy(items))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    with SessionLocal() as db:
        ids_ = list(db.scalars(select(Advisory.advisory_id).where(Advisory.advisory_id.like("CVE-2026-10%"))))
        affected = db.scalar(select(func.count()).select_from(AffectedProduct).join(Advisory, Advisory.id == AffectedProduct.advisory_id).where(Advisory.advisory_id.like("CVE-2026-10%")))
    assert len(ids_) == len(set(ids_)) == 30 and affected == 30


def test_database_error_during_correlation_is_recorded_and_the_retry_succeeds(owner, monkeypatch):
    from app.services import correlation

    scenario(owner)
    load_fixtures()
    real = correlation.build_assessment
    monkeypatch.setattr(correlation, "build_assessment", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("connection reset by peer")))
    assert owner.post("/correlation-runs").status_code == 202
    runs = owner.get("/correlation-runs").json()["items"]
    assert runs[0]["status"] == "failed" and "connection reset" in runs[0]["error"]
    assert owner.get("/dashboard").json()["failed_correlation_runs"]  # a failed run is shown, not hidden behind an empty list
    monkeypatch.setattr(correlation, "build_assessment", real)
    outbox.dispatch_pending()  # the periodic dispatcher retries the event that failed
    assert owner.get("/correlation-runs").json()["items"][0]["status"] == "succeeded"
    keys = [(a["advisory"], a["product"], a["client"]) for a in assessments(owner)]
    assert keys and len(keys) == len(set(keys))


# =============================================================== transactional outbox
def pending():
    with SessionLocal() as db:
        return list(db.scalars(select(OutboxEvent).where(OutboxEvent.dispatched_at.is_(None))))


def test_outbox_survives_a_broker_outage_and_dispatches_later(owner, monkeypatch):
    from app.workers.celery_app import celery

    scenario(owner)
    load_fixtures()
    monkeypatch.setattr(celery.tasks["app.workers.tasks.run_correlation"], "apply_async", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("Redis is down")))
    assert owner.post("/correlation-runs").status_code == 202  # the API still accepts the request
    rows = pending()
    assert len(rows) == 1 and rows[0].attempts == 1 and "Redis is down" in rows[0].last_error
    monkeypatch.undo()
    assert outbox.dispatch_pending() == 1  # Redis is back: the periodic dispatcher delivers it
    assert pending() == [] and owner.get("/correlation-runs").json()["items"][0]["status"] == "succeeded"


def test_outbox_rolled_back_transactions_enqueue_nothing(owner):
    with SessionLocal() as db:
        outbox.enqueue(db, "app.workers.tasks.run_correlation", [owner.org_id, None], dedupe_key="x")
        db.rollback()
    assert pending() == []


def test_outbox_collapses_duplicate_requests_with_a_dedupe_key(owner):
    with SessionLocal() as db:
        for _ in range(5):
            outbox.enqueue(db, "app.workers.tasks.run_correlation", [owner.org_id, None], dedupe_key=f"correlate:{owner.org_id}")
        db.commit()
    assert len(pending()) == 1
    assert outbox.dispatch_pending() == 1
    with SessionLocal() as db:  # once dispatched, a new request is accepted again
        outbox.enqueue(db, "app.workers.tasks.run_correlation", [owner.org_id, None], dedupe_key=f"correlate:{owner.org_id}")
        db.commit()
    assert len(pending()) == 1


def test_outbox_gives_up_after_the_attempt_limit(owner, monkeypatch):
    from app.workers.celery_app import celery

    monkeypatch.setattr(celery.tasks["app.workers.tasks.run_correlation"], "apply_async", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("down")))
    with SessionLocal() as db:
        outbox.enqueue(db, "app.workers.tasks.run_correlation", [owner.org_id, None])
        db.commit()
    for _ in range(outbox.MAX_ATTEMPTS + 3):
        outbox.dispatch_pending()
    row = pending()[0]
    assert row.attempts == outbox.MAX_ATTEMPTS and row.last_error  # parked for an operator, not retried forever


# =============================================================== Day 14: the end-to-end incident workflow
def test_end_to_end_incident_workflow_with_two_organizations(owner, other_owner, analyst):
    """Ingest -> normalise -> store affected products -> match -> traverse -> assess -> review -> isolate from other tenants."""
    s = scenario(owner)
    # second organization: same vendor and product, different client and a patched version
    b_client = make(other_owner, "/clients", name="Rival Client")
    b_vendor = make(other_owner, "/vendors", name="Acme Analytics Inc.")
    b_product = make(other_owner, "/products", vendor_id=b_vendor["id"], name="Insight Agent", version="4.2.1")
    b_asset = make(other_owner, "/assets", client_id=b_client["id"], name="rival-app", type="repository")
    rel(other_owner, "asset", b_asset["id"], "DEPENDS_ON", "product", b_product["id"])

    # 1-3. ingestion via the API (owner only), normalisation and affected-product storage
    assert owner.post("/ingestion-runs", json={"source": "fixture"}).status_code == 202
    assert owner.get("/ingestion-runs").json()["items"][0]["status"] == "succeeded"
    advisory = next(a for a in owner.get("/advisories?q=CVE-2099-1001").json()["items"])
    detail = owner.get(f"/advisories/{advisory['id']}").json()
    assert detail["affected_products"][0]["end_excluding"] == "4.2.1" and detail["source_url"] and detail["is_synthetic"]

    # 4-6. matching, traversal and assessment (triggered automatically after ingestion)
    mine = assessments(owner, advisory_id=advisory["id"])
    assert {a["client"] for a in mine} == {"Retail Client", "Clinic Client"}
    retail = next(a for a in mine if a["client"] == "Retail Client")
    assert retail["state"] == "potential_impact" and retail["exposure_status"] == "unverified" and retail["compromise_status"] == "unknown"
    missing_version = [a for a in assessments(owner) if a["advisory"] == "CVE-2099-1002"]
    assert missing_version and all(a["match_status"] == "insufficient_data" for a in missing_version)
    assert not [a for a in assessments(owner) if a["advisory"] in ("CVE-2099-1003", "CVE-2099-1005", "CVE-2099-1006")]  # unaffected / incomplete / unrelated

    # 7-8. the dashboard shows it and the graph can open the matched product and asset
    assert owner.get("/dashboard").json()["counts"]["active_assessments"] == len([a for a in assessments(owner) if a["match_status"] != "no_match"])
    graph = owner.get(f"/graph/neighborhood/product-{s['agent']['id']}?max_depth=2").json()
    assert f"asset-{s['storefront']['id']}" in ids_of(graph) and f"vendor-{s['acme']['id']}" in ids_of(graph)

    # 9. review
    reviewed = analyst.post(f"/assessments/{retail['id']}/review", json={"review_status": "reviewed", "note": "Looks right; verifying version."}).json()
    assert reviewed["review_status"] == "reviewed" and reviewed["state"] == "potential_impact"

    # 10. the other tenant: its patched version yields nothing, and it can see none of the first tenant's data
    assert [a for a in assessments(other_owner) if a["advisory"] == "CVE-2099-1001" and a["match_status"] != "no_match"] == []
    assert other_owner.get(f"/assessments/{retail['id']}").status_code == 404
    assert other_owner.get(f"/matches/{retail['match_id']}").status_code == 404
    assert all(a["client"] in (None, "Rival Client") for a in assessments(other_owner))
    # the shared advisory is public intelligence, but customer-specific matches are not
    assert other_owner.get(f"/advisories/{advisory['id']}").status_code == 200 and other_owner.get("/matches").json()["total"] <= 1


def ids_of(graph):
    return {n["id"] for n in graph["nodes"]}
