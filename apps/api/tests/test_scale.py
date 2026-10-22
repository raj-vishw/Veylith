"""Reliability and scale checks. Bounds are deliberately generous (they catch order-of-magnitude regressions,
e.g. an N+1 query or an unbounded graph response), and the measured timings are printed so they can be
recorded in docs/performance-report.md (run with `-s`)."""
import io
import time
import uuid

import pytest
from sqlalchemy import select, text

from app.db import org_session
from app.models import Asset, Client, Product, Relationship, Vendor

from .helpers import load_fixtures, make, rel


def timed(label, fn):
    start = time.perf_counter()
    out = fn()
    ms = (time.perf_counter() - start) * 1000
    print(f"[perf] {label}: {ms:.0f} ms")
    return out, ms


@pytest.fixture
def big_org(owner):
    """200 clients, 1,500 assets, 120 vendors with products, ~3,000 relationships (bulk inserted)."""
    org = uuid.UUID(owner.org_id)
    with org_session(org) as db:
        clients = [Client(organization_id=org, name=f"Client {i:03d}") for i in range(200)]
        db.add_all(clients)
        vendors = [Vendor(organization_id=org, name=f"Vendor {i:03d}", domain=f"vendor{i}.example.com", criticality="medium") for i in range(120)]
        db.add_all(vendors)
        db.flush()
        products = [Product(organization_id=org, vendor_id=v.id, name=f"Product {i:03d}", version="1.0.0") for i, v in enumerate(vendors)]
        db.add_all(products)
        assets = [Asset(organization_id=org, client_id=clients[i % 200].id, name=f"asset-{i:04d}", type="repository", criticality="medium") for i in range(1500)]
        db.add_all(assets)
        db.flush()
        rels = []
        for i, a in enumerate(assets):
            rels.append(Relationship(organization_id=org, source_type="asset", source_id=a.id, target_type="product", target_id=products[i % 120].id, rel_type="DEPENDS_ON", verification_status="verified"))
        for i, c in enumerate(clients):
            for k in range(3):
                rels.append(Relationship(organization_id=org, source_type="client", source_id=c.id, target_type="vendor", target_id=vendors[(i + k * 7) % 120].id, rel_type="USES_VENDOR"))
        db.add_all(rels)
        db.commit()
        return {"vendor": vendors[0].id, "client": clients[0].id}


def test_large_graph_is_capped_and_fast(owner, big_org):
    g, ms = timed("graph, unscoped (1.5k assets, capped)", lambda: owner.get("/graph").json())
    assert g["truncated"] and len(g["nodes"]) <= 400 and ms < 5000
    assert all(e["source"] in {n["id"] for n in g["nodes"]} for e in g["edges"])
    scoped, ms = timed("graph, scoped to one client", lambda: owner.get(f"/graph?client_id={big_org['client']}").json())
    assert len(scoped["nodes"]) < 60 and ms < 3000


def test_blast_radius_and_concentration_at_scale(owner, big_org):
    br, ms = timed("blast radius for a vendor shared by many clients", lambda: owner.get(f"/vendors/{big_org['vendor']}/blast-radius").json())
    assert br["summary"]["clients_with_recorded_dependency"] >= 5 and ms < 5000
    conc, ms = timed("concentration analysis", lambda: owner.get("/analysis/concentration").json())
    assert conc["items"] and ms < 5000


def test_listing_endpoints_paginate_at_scale(owner, big_org):
    r, ms = timed("assets page 1 of 1,500", lambda: owner.get("/assets?limit=50").json())
    assert r["total"] == 1500 and len(r["items"]) == 50 and ms < 1500
    r, ms = timed("relationships page", lambda: owner.get("/relationships?limit=100").json())
    assert len(r["items"]) == 100 and ms < 1500


def test_correlation_at_scale(owner, big_org):
    load_fixtures()
    owner.post("/vendors", json={"name": "Acme Analytics"})
    _, ms = timed("correlation, 120 products x all advisories", lambda: owner.post("/correlation-runs"))
    assert ms < 15000
    runs = owner.get("/correlation-runs").json()["items"]
    assert runs[0]["status"] == "succeeded"


def test_large_csv_import(owner):
    rows = ["name,website,category,criticality,access_level"] + [f"Vendor {i},v{i}.example.com,saas,medium,read" for i in range(5000)]
    data = ("\n".join(rows)).encode()
    files = lambda: {"file": ("big.csv", io.BytesIO(data), "text/csv")}  # noqa: E731
    preview, ms = timed("CSV preview, 5,000 rows", lambda: owner.post("/vendors/import?dry_run=true", files=files()).json())
    assert len(preview["accepted"]) == 5000 and ms < 8000
    done, ms = timed("CSV commit, 5,000 rows", lambda: owner.post("/vendors/import?dry_run=false", files=files()).json())
    assert owner.get("/vendors?limit=1").json()["total"] == 5000 and ms < 20000
    again = owner.post("/vendors/import?dry_run=true", files=files()).json()
    assert again["accepted"] == [] and len(again["duplicates"]) == 5000  # a repeated import is detected, not doubled


def test_csv_row_limit_is_enforced(owner):
    rows = ["name"] + [f"V{i}" for i in range(5001)]
    r = owner.post("/vendors/import", files={"file": ("big.csv", io.BytesIO("\n".join(rows).encode()), "text/csv")})
    assert r.status_code == 422 and "5000" in r.json()["detail"]


def test_report_with_a_long_timeline(owner):
    from app.services import reports

    case = make(owner, "/cases", title="Long running investigation")
    for i in range(150):
        make(owner, f"/cases/{case['id']}/notes", body=f"update {i}", visibility="customer")
    with org_session(uuid.UUID(owner.org_id)) as db:
        data = reports.collect(db, uuid.UUID(owner.org_id), uuid.UUID(case["id"]), "technical", "tester", "RPT-LONG")
        html, ms = timed("render 150-entry report to HTML", lambda: reports.render_html(data))
    assert "update 149" in html and ms < 3000


def test_database_connection_interruption_is_survivable(owner):
    """The pool is configured with pre-ping, so connections killed by a DB restart are replaced transparently."""
    from sqlalchemy import create_engine
    import os

    admin = create_engine(os.environ["MIGRATION_DATABASE_URL"])
    with admin.begin() as conn:
        conn.execute(text("select pg_terminate_backend(pid) from pg_stat_activity where datname = current_database() and usename = 'veylith_app' and pid <> pg_backend_pid()"))
    admin.dispose()
    assert owner.get("/clients").status_code in (200, 401)  # pool recovers; at worst the request retries on a fresh connection
    assert owner.get("/clients").status_code == 200


def test_concurrent_case_creation_gets_unique_numbers(owner):
    import concurrent.futures

    from tests.conftest import Api

    sessions = []
    for _ in range(6):  # signing in is rate limited, so sessions are created one by one
        api = Api()
        assert api.login("owner@msp.test").status_code == 200
        sessions.append(api)

    def create(i):
        r = sessions[i % 6].post("/cases", json={"title": f"Concurrent case {i}"})
        assert r.status_code == 201, r.text
        return r.json()["number"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        numbers = list(pool.map(create, range(12)))
    assert sorted(numbers) == list(range(1, 13))  # no duplicates, no gaps


# ---- Week 2: intelligence-side limits -----------------------------------------------------------------
def _advisory_batch(n):
    items = []
    for i in range(n):
        k = i % 1000
        vendor = f"vendor_{k:03d}" if k < 120 else f"other_vendor_{k}"  # ~12% of a realistic feed concerns vendors in this inventory
        items.append({"cve": {"id": f"CVE-2027-{i + 1:05d}", "published": "2027-01-01T00:00:00.000", "lastModified": "2027-01-02T00:00:00.000",
                              "descriptions": [{"lang": "en", "value": "Synthetic bulk advisory."}],
                              "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
                              "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:product_{k:03d}:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]}]}],
                              "references": []}})
    return items


def test_large_advisory_batch_ingest_and_repeat(owner, big_org):
    from app.db import SessionLocal
    from app.services import ingestion

    items = _advisory_batch(2000)

    def run():
        with SessionLocal() as db:
            r = ingestion.start_run(db, "nvd")
            ingestion._ingest_items(db, r, items, ingestion.parse_nvd_item, lambda i: i)
            return r

    first, ms = timed("ingest 2,000 advisories (first time)", run)
    assert first.records_new == 2000 and first.records_rejected == 0 and ms < 60000
    second, ms2 = timed("ingest the same 2,000 advisories again (idempotent)", run)
    assert second.records_new == 0 and second.records_updated == 0 and ms2 < ms


def test_correlation_repeated_re_evaluation_stays_fast_and_stable(owner, big_org):
    from app.db import SessionLocal
    from app.services import ingestion

    items = _advisory_batch(2000)
    with SessionLocal() as db:
        r = ingestion.start_run(db, "nvd")
        ingestion._ingest_items(db, r, items, ingestion.parse_nvd_item, lambda i: i)
    owner.post("/correlation-runs")
    count = owner.get("/matches?limit=1").json()["total"]
    assert count > 0
    for i in range(3):
        _, ms = timed(f"re-evaluation #{i + 1} (120 products x 2,000 advisories)", lambda: owner.post("/correlation-runs"))
        assert ms < 20000
    assert owner.get("/matches?limit=1").json()["total"] == count  # repeated runs do not multiply records
    run = owner.get("/correlation-runs").json()["items"][0]
    assert run["status"] == "succeeded" and run["assessments_created"] == 0


def test_dashboard_and_filtered_queue_with_many_assessments(owner, big_org):
    from app.db import SessionLocal
    from app.services import ingestion

    with SessionLocal() as db:
        r = ingestion.start_run(db, "nvd")
        ingestion._ingest_items(db, r, _advisory_batch(2000), ingestion.parse_nvd_item, lambda i: i)
    owner.post("/correlation-runs")
    _, ms = timed("dashboard", lambda: owner.get("/dashboard"))
    assert ms < 5000
    q = "/assessments?limit=50&priority=high&match_status=matched&asset_criticality=medium&known_exploited=false&review_status=unreviewed"
    out, ms = timed("assessment queue with 6 filters", lambda: owner.get(q).json())
    assert out["total"] >= 0 and ms < 5000
    _, ms = timed("neighborhood expansion (depth 2, 100 nodes)", lambda: owner.get(f"/graph/neighborhood/vendor-{big_org['vendor']}?max_depth=2&max_nodes=100"))
    assert ms < 3000
    _, ms = timed("global advisory search", lambda: owner.get("/advisories?q=CVE-2027-0100&limit=25"))
    assert ms < 3000
