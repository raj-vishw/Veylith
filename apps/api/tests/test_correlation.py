"""The Week-2 validation scenario: seeded inventory x synthetic advisories -> qualified assessments."""
import pytest

from .helpers import load_fixtures, make, rel, scenario

FORBIDDEN_CLAIMS = ("compromise_confirmed", "exposure_verified", "confirmed_dependency")


@pytest.fixture
def seeded(owner):
    ids = scenario(owner)
    load_fixtures()
    assert owner.post("/correlation-runs").status_code == 202
    items = owner.get("/assessments?limit=100&include_no_match=true").json()["items"]
    return ids, items


def by(items, advisory, **match):
    return [a for a in items if a["advisory"] == advisory and all(a.get(k) == v for k, v in match.items())]


def test_known_affected_product_and_version_is_potential_impact(owner, seeded):
    ids, items = seeded
    hits = by(items, "CVE-2099-1001")
    assert {a["client"] for a in hits} == {"Retail Client", "Clinic Client"}  # vendor linked to multiple clients
    retail = by(items, "CVE-2099-1001", client="Retail Client")[0]
    assert retail["state"] == "potential_impact" and retail["version_status"] == "in_range" and retail["match_type"] == "name"
    assert retail["known_exploited"] is True and retail["synthetic"] is True


def test_asset_level_path_beats_vendor_level_link(owner, seeded):
    ids, items = seeded
    retail = owner.get(f"/assessments/{by(items, 'CVE-2099-1001', client='Retail Client')[0]['id']}").json()
    clinic = owner.get(f"/assessments/{by(items, 'CVE-2099-1001', client='Clinic Client')[0]['id']}").json()
    assert [s["step"] for s in retail["evidence"]["path"]] == ["advisory", "product", "asset"]
    assert retail["relationship_confidence"] == "high" and retail["impact_confidence"] == "medium"
    assert [s["step"] for s in clinic["evidence"]["path"]] == ["advisory", "product"]  # client uses the vendor; product use unproven
    assert clinic["relationship_confidence"] == "low" and clinic["impact_confidence"] == "low"
    assert any("No asset-level relationship" in u for u in clinic["unknowns"])


def test_unaffected_version_creates_no_active_assessment(owner, seeded):
    ids, items = seeded
    # SSO Gateway 1.9.0 vs an advisory for exactly 1.8.0
    assert not by(items, "CVE-2099-1003")
    assert owner.get("/assessments?limit=100").json()["items"]  # while other advisories did match


def test_missing_version_is_insufficient_data(owner, seeded):
    ids, items = seeded
    hits = by(items, "CVE-2099-1002")
    assert hits and all(a["state"] == "insufficient_data" and a["version_status"] == "unknown" for a in hits)
    detail = owner.get(f"/assessments/{hits[0]['id']}").json()
    assert any("version is not recorded" in u for u in detail["unknowns"])


def test_kev_without_versions_cannot_claim_a_match_beyond_unknown(owner, seeded):
    ids, items = seeded
    hits = by(items, "CVE-2099-1009")
    assert hits and all(a["state"] == "insufficient_data" for a in hits)


def test_similar_product_name_is_flagged_for_review_not_matched(owner, seeded):
    ids, items = seeded
    fuzzy = by(items, "CVE-2099-1004")
    assert fuzzy and all(a["match_type"] == "fuzzy" and a["state"] == "insufficient_data" and a["match_confidence"] == "low" for a in fuzzy)


def test_advisory_without_product_details_and_unrelated_vendor_do_not_match(owner, seeded):
    ids, items = seeded
    assert not by(items, "CVE-2099-1005")
    assert not [a for a in items if a["advisory"] == "CVE-2099-1006" and a["state"] != "no_match_found"]


def test_engine_never_declares_compromise_or_verified_exposure(owner, seeded):
    ids, items = seeded
    assert items and not [a for a in items if a["state"] in FORBIDDEN_CLAIMS]
    for a in items[:5]:
        d = owner.get(f"/assessments/{a['id']}").json()
        assert any("not evidence of compromise" in u for u in d["unknowns"])


def test_prioritisation_is_explained_factor_by_factor(owner, seeded):
    ids, items = seeded
    d = owner.get(f"/assessments/{by(items, 'CVE-2099-1001', client='Retail Client')[0]['id']}").json()
    names = {f["factor"] for f in d["priority_factors"]}
    assert {"Advisory severity", "Known exploitation", "Asset criticality", "Internet exposure", "Vendor access", "Evidence quality"} <= names
    assert d["priority"] in ("high", "critical")
    clinic = owner.get(f"/assessments/{by(items, 'CVE-2099-1001', client='Clinic Client')[0]['id']}").json()
    assert sum(f["points"] for f in clinic["priority_factors"]) < sum(f["points"] for f in d["priority_factors"])


def test_confidence_is_tracked_in_separate_dimensions(owner, seeded):
    ids, items = seeded
    a = by(items, "CVE-2099-1001", client="Retail Client")[0]
    assert {"source_confidence", "match_confidence", "relationship_confidence", "impact_confidence"} <= set(a)
    assert a["source_confidence"] == "high" and a["impact_confidence"] != "high"  # a strong match is not strong impact


def test_sources_and_timestamps_are_retained_on_the_assessment(owner, seeded):
    ids, items = seeded
    d = owner.get(f"/assessments/{by(items, 'CVE-2099-1001', client='Retail Client')[0]['id']}").json()
    adv = d["evidence"]["advisory"]
    assert adv["source_url"] and adv["published_at"] and adv["modified_at"] and adv["synthetic"] is True
    assert d["synthetic_notice"]


def test_correlation_is_idempotent(owner, seeded):
    ids, items = seeded
    owner.post("/correlation-runs")
    again = owner.get("/assessments?limit=100&include_no_match=true").json()
    assert again["total"] == len(items)
    runs = owner.get("/correlation-runs").json()["items"]
    assert runs[0]["status"] == "succeeded" and runs[0]["assessments_created"] == 0


def test_inventory_change_recalculates_and_explains(owner, seeded):
    ids, items = seeded
    # patch the product past the fixed version -> the match should disappear, with a recorded reason
    owner.patch(f"/products/{ids['agent']['id']}", json={"version": "4.2.1"})
    owner.post("/correlation-runs")
    retail = owner.get(f"/assessments/{by(items, 'CVE-2099-1001', client='Retail Client')[0]['id']}").json()
    assert retail["state"] == "no_match_found"
    assert any(e["event_type"] == "state_changed" and "inventory" in e["note"] for e in retail["events"])
    # and no longer shows in the default list
    assert not [a for a in owner.get("/assessments?limit=100").json()["items"] if a["advisory"] == "CVE-2099-1001" and a["client"] == "Retail Client"]


def test_new_dependency_adds_assessments_on_next_run(owner, seeded):
    ids, items = seeded
    third = make(owner, "/clients", name="Third Client")
    asset = make(owner, "/assets", client_id=third["id"], name="payments", type="business_application", criticality="high")
    rel(owner, "asset", asset["id"], "DEPENDS_ON", "product", ids["agent"]["id"])
    owner.post("/correlation-runs")
    assert by(owner.get("/assessments?limit=100").json()["items"], "CVE-2099-1001", client="Third Client")


def test_analyst_review_flow_and_guardrails(owner, analyst, viewer, seeded):
    ids, items = seeded
    aid = by(items, "CVE-2099-1001", client="Retail Client")[0]["id"]
    assert viewer.post(f"/assessments/{aid}/review", json={"review_status": "reviewed"}).status_code == 403
    ok = analyst.post(f"/assessments/{aid}/review", json={"review_status": "reviewed"})
    assert ok.status_code == 200 and ok.json()["review_status"] == "reviewed"
    # moving to a stronger state requires a reason
    assert analyst.post(f"/assessments/{aid}/review", json={"review_status": "reviewed", "state": "exposure_verified"}).status_code == 422
    ok = analyst.post(f"/assessments/{aid}/review", json={"review_status": "reviewed", "state": "exposure_verified", "note": "Confirmed v4.1.0 deployed in prod."})
    assert ok.json()["state"] == "exposure_verified"
    # compromise needs verified evidence
    case = make(owner, "/cases", title="Retail agent", assessment_ids=[aid])
    bad = analyst.post(f"/assessments/{aid}/review", json={"review_status": "reviewed", "state": "compromise_confirmed", "note": "Attacker seen."})
    assert bad.status_code == 422
    ev = make(owner, f"/cases/{case['id']}/evidence", kind="note", title="EDR alert", excerpt="Beaconing from storefront-api", assessment_id=aid)
    assert owner.post(f"/evidence/{ev['id']}/verify", json={"verification_status": "verified"}).status_code == 200
    good = analyst.post(f"/assessments/{aid}/review", json={"review_status": "reviewed", "state": "compromise_confirmed", "note": "EDR evidence verified."})
    assert good.status_code == 200 and good.json()["state"] == "compromise_confirmed"
    states = [(e["from_state"], e["to_state"]) for e in good.json()["events"] if e["event_type"] == "reviewed"]
    assert ("potential_impact", "exposure_verified") in states and ("exposure_verified", "compromise_confirmed") in states


def test_analyst_decisions_survive_recalculation(owner, seeded):
    ids, items = seeded
    aid = by(items, "CVE-2099-1001", client="Retail Client")[0]["id"]
    owner.post(f"/assessments/{aid}/review", json={"review_status": "reviewed", "state": "exposure_verified", "note": "verified"})
    third = make(owner, "/clients", name="Another")
    rel(owner, "client", third["id"], "USES_VENDOR", "vendor", ids["acme"]["id"])
    owner.post("/correlation-runs")
    assert owner.get(f"/assessments/{aid}").json()["state"] == "exposure_verified"


def test_upstream_advisory_change_reopens_review(owner, seeded):
    from app.db import SessionLocal
    from app.models import Advisory
    from app.services import ingestion
    from sqlalchemy import select
    import copy
    import json
    from pathlib import Path

    ids, items = seeded
    aid = by(items, "CVE-2099-1001", client="Retail Client")[0]["id"]
    owner.post(f"/assessments/{aid}/review", json={"review_status": "reviewed"})
    nvd = json.loads((ingestion.FIXTURE_DIR / "synthetic_nvd.json").read_text())
    item = copy.deepcopy(next(v for v in nvd["vulnerabilities"] if v["cve"]["id"] == "CVE-2099-1001"))
    item["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "4.0.0"  # vendor narrowed the range
    item["cve"]["lastModified"] = "2099-02-01T00:00:00.000"
    with SessionLocal() as db:
        adv = ingestion.parse_nvd_item(item, source="fixture")
        assert ingestion.upsert_advisory(db, adv, item, synthetic=True) == "updated"
        db.commit()
        pk = db.scalar(select(Advisory.id).where(Advisory.advisory_id == "CVE-2099-1001"))
    from app.services.correlation import correlate_all_orgs
    correlate_all_orgs(SessionLocal, {pk})
    d = owner.get(f"/assessments/{aid}").json()
    assert d["state"] == "no_match_found"  # 4.1.0 is no longer in the affected range
    assert any(e["note"] for e in d["events"] if e["event_type"] in ("state_changed", "advisory_changed"))


def test_dashboard_summarises_the_workload(owner, seeded):
    d = owner.get("/dashboard").json()
    assert d["counts"]["active_assessments"] > 0 and d["counts"]["unreviewed"] == d["counts"]["active_assessments"]
    assert d["new_advisories"] and d["affected_clients"] and d["high_priority_assessments"]
    assert d["failed_ingestion_runs"] == []


def test_assessment_filters(owner, seeded):
    assert owner.get("/assessments?state=insufficient_data").json()["total"] > 0
    assert all(a["state"] == "insufficient_data" for a in owner.get("/assessments?state=insufficient_data").json()["items"])
    assert all(a["client"] == "Retail Client" for a in owner.get(f"/assessments?client_id={seeded[0]['retail']['id']}").json()["items"])
    assert owner.get("/assessments?severity=critical").json()["total"] > 0
    first = owner.get("/assessments?limit=100").json()["items"]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert [order[a["priority"]] for a in first] == sorted(order[a["priority"]] for a in first)


def test_failed_correlation_is_visible(owner, monkeypatch):
    from app.services import correlation

    scenario(owner)
    load_fixtures()

    def boom(*a, **k):
        raise RuntimeError("database hiccup")

    monkeypatch.setattr(correlation, "build_assessment", boom)
    # The request is accepted (work is queued through the outbox); the failure is recorded, visible, and retried later.
    assert owner.post("/correlation-runs").status_code == 202
    runs = owner.get("/correlation-runs").json()["items"]
    assert runs[0]["status"] == "failed" and "hiccup" in runs[0]["error"]
    assert owner.get("/dashboard").json()["failed_correlation_runs"]
