"""Ingestion tests run entirely offline: fixtures plus an httpx mock transport. No test touches the network."""
import os

import httpx
import pytest
from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import Advisory, AdvisoryRevision, AffectedProduct, IngestionRun, SourceRecord
from app.services import ingestion

NVD_ITEM = {
    "cve": {
        "id": "CVE-2025-0001",
        "published": "2025-03-01T10:00:00.000", "lastModified": "2025-03-02T10:00:00.000",
        "descriptions": [{"lang": "es", "value": "hola"}, {"lang": "en", "value": "Widget before 2.0 allows RCE."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:widgetco:widget:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
        ]}]}],
        "references": [{"url": "https://widgetco.example/advisory", "source": "widgetco", "tags": ["Vendor Advisory"]}],
    }
}


def run_for(db, source="fixture"):
    return ingestion.start_run(db, source)


def test_parse_nvd_item():
    adv = ingestion.parse_nvd_item(NVD_ITEM)
    assert adv.advisory_id == "CVE-2025-0001" and adv.severity == "critical" and adv.cvss_score == 9.8
    assert adv.description == "Widget before 2.0 allows RCE."
    assert adv.published_at.tzinfo is not None
    assert adv.source_url == "https://nvd.nist.gov/vuln/detail/CVE-2025-0001"
    assert [(a.vendor, a.product, a.end_excluding, a.vulnerable) for a in adv.affected][0] == ("widgetco", "widget", "2.0", True)
    assert "https://widgetco.example/advisory" in adv.mitigation


def test_malformed_record_is_rejected():
    with pytest.raises(ingestion.IngestionError):
        ingestion.parse_nvd_item({"cve": {"descriptions": []}})
    with pytest.raises(ingestion.IngestionError):
        ingestion.parse_kev_item({"vendorProject": "x"})


def test_kev_without_versions_is_marked_version_unknown():
    adv = ingestion.parse_kev_item({"cveID": "CVE-2025-9", "vendorProject": "Globex", "product": "Vault Sync", "dateAdded": "2025-01-02", "requiredAction": "Patch."})
    assert adv.known_exploited and adv.affected[0].exact_version == "?" and str(adv.kev_added_at) == "2025-01-02"


def test_fixture_ingestion_is_idempotent():
    with SessionLocal() as db:
        first = run_for(db)
        ingestion.ingest_fixture(db, first)
        assert first.status == "succeeded" and first.records_new > 0
        advisories = db.scalar(select(func.count()).select_from(Advisory))
        affected = db.scalar(select(func.count()).select_from(AffectedProduct))

        second = run_for(db)
        ingestion.ingest_fixture(db, second)
        assert second.records_new == 0 and second.records_updated == 0
        assert db.scalar(select(func.count()).select_from(Advisory)) == advisories
        assert db.scalar(select(func.count()).select_from(AffectedProduct)) == affected


def test_fixture_data_is_labelled_synthetic():
    with SessionLocal() as db:
        ingestion.ingest_fixture(db, run_for(db))
        advisories = list(db.scalars(select(Advisory)))
        assert advisories and all(a.is_synthetic for a in advisories)
        assert all("SYNTHETIC" in a.description for a in advisories)


def test_kev_merges_into_the_nvd_advisory_without_clobbering_it():
    with SessionLocal() as db:
        ingestion.ingest_fixture(db, run_for(db))
        a = db.scalar(select(Advisory).where(Advisory.advisory_id == "CVE-2099-1001"))
        assert a.known_exploited and a.kev_added_at is not None
        assert a.severity == "critical" and a.cvss_score == 9.8  # NVD detail intact
        assert db.scalar(select(func.count()).select_from(AffectedProduct).where(AffectedProduct.advisory_id == a.id)) == 1  # no KEV placeholder added


def test_raw_payload_and_provenance_are_kept_separately():
    with SessionLocal() as db:
        adv = ingestion.parse_nvd_item(NVD_ITEM)
        assert ingestion.upsert_advisory(db, adv, NVD_ITEM) == "new"
        db.commit()
        rec = db.scalar(select(SourceRecord).where(SourceRecord.external_id == "CVE-2025-0001"))
        assert rec.raw == NVD_ITEM and rec.source_url and rec.retrieved_at is not None and len(rec.content_hash) == 64
        a = db.scalar(select(Advisory).where(Advisory.advisory_id == "CVE-2025-0001"))
        assert a.first_seen_at is not None and a.source_url.endswith("CVE-2025-0001")


def test_upstream_modification_updates_and_records_a_revision():
    import copy

    with SessionLocal() as db:
        assert ingestion.upsert_advisory(db, ingestion.parse_nvd_item(NVD_ITEM), NVD_ITEM) == "new"
        db.commit()
        before = db.scalar(select(Advisory).where(Advisory.advisory_id == "CVE-2025-0001")).content_hash
        changed = copy.deepcopy(NVD_ITEM)
        changed["cve"]["lastModified"] = "2025-03-09T10:00:00.000"
        changed["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "2.5"
        changed["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 7.0
        changed["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] = "HIGH"
        assert ingestion.upsert_advisory(db, ingestion.parse_nvd_item(changed), changed) == "updated"
        db.commit()
        a = db.scalar(select(Advisory).where(Advisory.advisory_id == "CVE-2025-0001"))
        assert a.severity == "high" and a.content_hash != before
        ap = db.scalar(select(AffectedProduct).where(AffectedProduct.advisory_id == a.id))
        assert ap.end_excluding == "2.5"
        rev = db.scalar(select(AdvisoryRevision).where(AdvisoryRevision.advisory_id == a.id))
        assert rev.changes["severity"] == {"from": "critical", "to": "high"}
        assert "affected_products" in rev.changes and rev.changes["cvss_score"]["to"] == 7.0


def test_one_bad_record_does_not_abort_the_batch():
    with SessionLocal() as db:
        run = run_for(db, "nvd")
        items = [{"cve": {"descriptions": []}}, NVD_ITEM]
        ingestion._ingest_items(db, run, items, ingestion.parse_nvd_item, lambda i: i)
        assert run.records_seen == 2 and run.records_new == 1


# ---- HTTP behaviour (mock transport; the sleeps are stubbed so tests are instant) ----------------
def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_retries_on_rate_limit_then_succeeds():
    calls = {"n": 0}
    sleeps = []

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429, headers={"retry-after": "2"})
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    out = ingestion.fetch_json(client_for(handler), "https://nvd.test/api", sleep=sleeps.append)
    assert out["totalResults"] == 0 and calls["n"] == 3 and sleeps == [2.0, 2.0]


def test_gives_up_after_bounded_retries():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503)

    with pytest.raises(ingestion.IngestionError):
        ingestion.fetch_json(client_for(handler), "https://nvd.test/api", sleep=lambda s: None)
    assert calls["n"] == 5  # 1 attempt + 4 retries, never unbounded


def test_client_errors_are_not_retried():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(404)

    with pytest.raises(ingestion.IngestionError):
        ingestion.fetch_json(client_for(handler), "https://nvd.test/api", sleep=lambda s: None)
    assert calls["n"] == 1


def test_nvd_ingest_paginates_and_records_success():
    pages = []

    def handler(request):
        start = int(request.url.params["startIndex"])
        pages.append(start)
        item = {"cve": {**NVD_ITEM["cve"], "id": f"CVE-2025-{start + 1:04d}"}}
        return httpx.Response(200, json={"vulnerabilities": [item], "totalResults": 2, "startIndex": start})

    with SessionLocal() as db:
        run = run_for(db, "nvd")
        changed = ingestion.ingest_nvd(db, client_for(handler), run, sleep=lambda s: None)
        assert run.status == "succeeded" and run.records_new == 2 and len(changed) == 2
    assert pages[:2] == [0, 1]


def test_nvd_failure_is_recorded_and_visible():
    with SessionLocal() as db:
        run = run_for(db, "nvd")
        ingestion.ingest_nvd(db, client_for(lambda r: httpx.Response(500)), run, sleep=lambda s: None)
        assert run.status == "failed" and "giving up" in run.error and run.finished_at is not None


def test_kev_ingest_from_mock_feed():
    feed = {"vulnerabilities": [{"cveID": "CVE-2025-7777", "vendorProject": "Globex", "product": "Vault Sync", "dateAdded": "2025-02-01", "requiredAction": "Patch."}]}
    with SessionLocal() as db:
        run = run_for(db, "kev")
        ingestion.ingest_kev(db, client_for(lambda r: httpx.Response(200, json=feed)), run, sleep=lambda s: None)
        assert run.status == "succeeded" and run.records_new == 1
        assert db.scalar(select(Advisory).where(Advisory.advisory_id == "CVE-2025-7777")).known_exploited


def test_only_configured_endpoints_are_ever_requested():
    seen = []

    def handler(request):
        seen.append(str(request.url.host))
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    with SessionLocal() as db:
        ingestion.ingest_nvd(db, client_for(handler), run_for(db, "nvd"), sleep=lambda s: None)
        ingestion.ingest_kev(db, client_for(handler), run_for(db, "kev"), sleep=lambda s: None)
    assert set(seen) == {"services.nvd.nist.gov", "www.cisa.gov"}


# ---- API ----------------------------------------------------------------------------------------
def test_ingestion_api_requires_owner_and_reports_health(owner, analyst):
    assert analyst.post("/ingestion-runs", json={"source": "fixture"}).status_code == 403
    r = owner.post("/ingestion-runs", json={"source": "fixture"})
    assert r.status_code == 202
    runs = owner.get("/ingestion-runs").json()["items"]
    assert runs[0]["status"] == "succeeded" and runs[0]["records_new"] > 0
    assert owner.post("/ingestion-runs", json={"source": "https://evil.example/feed"}).status_code == 422  # no arbitrary URLs
    health = {s["source"]: s for s in owner.get("/ingestion-health").json()["sources"]}
    assert set(health) == {"nvd", "kev"}


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("VEYLITH_LIVE_TESTS") != "1", reason="live-source smoke test; set VEYLITH_LIVE_TESTS=1")
def test_live_kev_feed_is_parseable():
    with httpx.Client() as client:
        data = ingestion.fetch_json(client, ingestion.get_settings().kev_url)
    assert data["vulnerabilities"] and ingestion.parse_kev_item(data["vulnerabilities"][0]).advisory_id.startswith("CVE-")
