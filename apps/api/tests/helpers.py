"""Seeds the standard scenario through the public API, so tests exercise the same paths as users."""

import os
import secrets

# No password literal in the repository: taken from TEST_PASSWORD if set, otherwise random for each test run.
TEST_PASSWORD = os.environ.get("TEST_PASSWORD") or secrets.token_urlsafe(18)


def make(api, path, **body):
    r = api.post(path, json=body)
    assert r.status_code in (200, 201, 202), (path, r.status_code, r.text)
    return r.json()


def rel(api, source_type, source_id, rel_type, target_type, target_id, **extra):
    if extra.get("verification_status") == "verified":
        extra.setdefault("verification_method", "manual_review")
    return make(api, "/relationships", source_type=source_type, source_id=source_id, target_type=target_type, target_id=target_id, rel_type=rel_type, **extra)


def load_fixtures():
    """Ingest the bundled synthetic advisories directly (no network)."""
    from app.db import SessionLocal
    from app.services import ingestion

    with SessionLocal() as db:
        run = ingestion.start_run(db, "fixture")
        return ingestion.ingest_fixture(db, run)


def scenario(api):
    """Two clients; Acme Analytics Insight Agent 4.1.0 (vulnerable) used by one client's production repo,
    Globex Vault Sync without a version, SSO Gateway at a patched version, and an unrelated vendor."""
    retail = make(api, "/clients", name="Retail Client", industry="retail", criticality="high")
    clinic = make(api, "/clients", name="Clinic Client", industry="health")
    acme = make(api, "/vendors", name="Acme Analytics Inc.", website="https://www.acme-analytics.com", category="analytics", access_level="read", criticality="high")
    globex = make(api, "/vendors", name="Globex Backup", website="globex-backup.io", category="backup", access_level="admin")
    initech = make(api, "/vendors", name="Initech Auth", category="identity")
    umbrella = make(api, "/vendors", name="Umbrella Hosting", category="hosting")
    agent = make(api, "/products", vendor_id=acme["id"], name="Insight Agent", version="4.1.0")
    vault = make(api, "/products", vendor_id=globex["id"], name="Vault Sync", version="")
    sso = make(api, "/products", vendor_id=initech["id"], name="SSO Gateway", version="1.9.0")
    panel = make(api, "/products", vendor_id=umbrella["id"], name="Cloud Panel", version="9.9")
    storefront = make(api, "/assets", client_id=retail["id"], name="storefront-api", type="repository", criticality="critical", internet_exposed=True)
    intranet = make(api, "/assets", client_id=clinic["id"], name="intranet", type="business_application", criticality="low")
    rel(api, "client", retail["id"], "USES_VENDOR", "vendor", acme["id"], verification_status="verified")
    rel(api, "client", clinic["id"], "USES_VENDOR", "vendor", acme["id"])
    rel(api, "asset", storefront["id"], "DEPENDS_ON", "product", agent["id"], verification_status="verified")
    rel(api, "client", retail["id"], "USES_VENDOR", "vendor", globex["id"])
    rel(api, "asset", intranet["id"], "DEPENDS_ON", "product", vault["id"])
    return {"retail": retail, "clinic": clinic, "acme": acme, "globex": globex, "initech": initech, "umbrella": umbrella,
            "agent": agent, "vault": vault, "sso": sso, "panel": panel, "storefront": storefront, "intranet": intranet}
