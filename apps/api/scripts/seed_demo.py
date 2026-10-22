"""Seed a synthetic demo organization through the public API.

    docker compose run --rm api python -m scripts.seed_demo --base-url http://api:8000

Everything created here is synthetic: fictional vendors, fictional clients, and advisories from the bundled
synthetic fixtures (CVE-2099-*). The organization is flagged is_demo so the UI and reports label it clearly.
"""
import argparse
import os
import secrets
import sys
import time

import httpx
from sqlalchemy import create_engine, text

DEMO_ORG = "Northwind MSP (DEMO)"


class Client:
    def __init__(self, base: str, origin: str):
        self.http = httpx.Client(base_url=base.rstrip("/") + "/api/v1", timeout=30, headers={"Origin": origin})
        self.csrf = ""

    def call(self, method, path, **kw):
        r = self.http.request(method, path, headers={"X-CSRF-Token": self.csrf}, **kw)
        if r.status_code >= 400:
            sys.exit(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else None

    def auth(self, path, body):
        r = self.http.post(path, json=body)
        if r.status_code >= 400:
            return r
        self.csrf = r.json()["csrf_token"]
        return r


def wait(predicate, what: str, timeout: float = 90.0) -> None:
    """Background jobs run in the worker, so poll until they have finished."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(1)
    sys.exit(f"Timed out waiting for {what}. Is the worker running?")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--origin", default=os.environ.get("TRUSTED_ORIGINS", "http://localhost:3000").split(",")[0])
    ap.add_argument("--password", default=os.environ.get("DEMO_PASSWORD"))
    ap.add_argument("--with-rival", action="store_true", help="also create a second organization for isolation demos")
    args = ap.parse_args()
    if os.environ.get("ENVIRONMENT") == "production":
        sys.exit("Refusing to seed demo data in production.")
    password = args.password or secrets.token_urlsafe(14)

    api = Client(args.base_url, args.origin)
    owner_email = os.environ.get("DEMO_OWNER_EMAIL", "demo.owner@example.com")
    analyst_email = os.environ.get("DEMO_ANALYST_EMAIL", "demo.analyst@example.com")
    viewer_email = os.environ.get("DEMO_VIEWER_EMAIL", "demo.viewer@example.com")
    reg = api.auth("/auth/register", {"email": owner_email, "password": password, "organization_name": DEMO_ORG, "display_name": "Demo Owner"})
    if reg.status_code >= 400:
        print(f"Demo organization already exists or registration is closed ({reg.status_code}); nothing to do.")
        return
    org_id = reg.json()["organization"]["id"]
    if os.environ.get("MIGRATION_DATABASE_URL"):
        with create_engine(os.environ["MIGRATION_DATABASE_URL"]).begin() as conn:
            conn.execute(text("update organizations set is_demo = true where id = :i"), {"i": org_id})

    for email, role, name in ((analyst_email, "analyst", "Demo Analyst"), (viewer_email, "viewer", "Demo Viewer")):
        api.call("POST", "/members", json={"email": email, "password": password, "role": role, "display_name": name})

    # --- clients, vendors, products, assets --------------------------------------------------
    retail = api.call("POST", "/clients", json={"name": "Contoso Retail (synthetic)", "industry": "retail", "criticality": "high"})
    clinic = api.call("POST", "/clients", json={"name": "Fabrikam Clinics (synthetic)", "industry": "healthcare", "criticality": "critical"})
    logistics = api.call("POST", "/clients", json={"name": "Tailspin Logistics (synthetic)", "industry": "logistics"})

    def vendor(name, site, category, access, crit="medium", desc=""):
        return api.call("POST", "/vendors", json={"name": name, "website": site, "category": category, "access_level": access, "criticality": crit,
                                                  "description": desc or "Synthetic demo vendor.", "source": "demo seed", "owner": "Platform team"})

    acme = vendor("Acme Analytics Inc.", "acme-analytics.example.com", "analytics", "read", "high", "Product analytics agent installed in client web apps.")
    globex = vendor("Globex Backup", "globex-backup.example.com", "backup", "admin", "critical", "Backup replication service with admin access to cloud accounts.")
    initech = vendor("Initech Auth", "initech-auth.example.com", "identity", "write", "high")
    umbrella = vendor("Umbrella Hosting", "umbrella-hosting.example.com", "hosting", "none")

    agent = api.call("POST", "/products", json={"vendor_id": acme["id"], "name": "Insight Agent", "version": "4.1.0", "source": "demo seed"})
    api.call("POST", "/products", json={"vendor_id": acme["id"], "name": "Insight Agent", "version": "4.2.1", "source": "demo seed", "confidence": "high"})
    vault = api.call("POST", "/products", json={"vendor_id": globex["id"], "name": "Vault Sync", "version": "", "source": "demo seed"})
    api.call("POST", "/products", json={"vendor_id": initech["id"], "name": "SSO Gateway", "version": "1.9.0", "source": "demo seed"})
    api.call("POST", "/products", json={"vendor_id": umbrella["id"], "name": "Cloud Panel", "version": "3.4", "source": "demo seed"})

    def asset(client, name, kind, crit, exposed=False, env="production", sens="internal"):
        return api.call("POST", "/assets", json={"client_id": client["id"], "name": name, "type": kind, "criticality": crit, "internet_exposed": exposed,
                                                 "environment": env, "data_sensitivity": sens})

    storefront = asset(retail, "storefront-api", "repository", "critical", True, sens="confidential")
    checkout = asset(retail, "checkout-service", "business_application", "high", True)
    ehr = asset(clinic, "patient-portal", "business_application", "critical", True, sens="restricted")
    aws = asset(clinic, "clinic-prod-aws", "cloud_resource", "critical", sens="restricted")
    routing = asset(logistics, "routing-engine", "repository", "high")

    def rel(st, sid, rt, tt, tid, **kw):
        if kw.get("verification_status") == "verified":
            kw.setdefault("verification_method", "manual_review")
        return api.call("POST", "/relationships", json={"source_type": st, "source_id": sid, "target_type": tt, "target_id": tid, "rel_type": rt, **kw})

    for c in (retail, clinic, logistics):
        rel("client", c["id"], "USES_VENDOR", "vendor", acme["id"], verification_status="verified" if c is retail else "unverified", source="demo seed")
    rel("client", clinic["id"], "USES_VENDOR", "vendor", globex["id"], verification_status="verified")
    rel("client", retail["id"], "USES_VENDOR", "vendor", initech["id"], verification_status="verified")
    rel("asset", storefront["id"], "DEPENDS_ON", "product", agent["id"], verification_status="verified", evidence="Dependency manifest reviewed", confidence="high")
    rel("asset", checkout["id"], "DEPENDS_ON", "vendor", initech["id"], verification_status="verified")
    rel("asset", ehr["id"], "DEPENDS_ON", "product", vault["id"])
    rel("vendor", globex["id"], "HAS_ACCESS_TO", "asset", aws["id"], access_scope="admin: snapshot + restore", verification_status="verified", confidence="high")
    rel("vendor", acme["id"], "HAS_ACCESS_TO", "asset", storefront["id"], access_scope="read: telemetry bucket", verification_status="verified")
    rel("asset", routing["id"], "DEPENDS_ON", "product", agent["id"])
    rel("vendor", initech["id"], "DEPENDS_ON", "vendor", umbrella["id"], source="demo seed")

    # --- synthetic intelligence, correlation ------------------------------------------------------
    api.call("POST", "/ingestion-runs", json={"source": "fixture"})
    wait(lambda: api.call("GET", "/ingestion-runs")["items"][0]["status"] != "running", "ingestion")
    api.call("POST", "/correlation-runs")
    wait(lambda: api.call("GET", "/assessments?limit=1")["total"] > 0, "correlation")

    # --- one worked investigation ----------------------------------------------------------------
    items = api.call("GET", "/assessments?limit=100")["items"]
    target = next(a for a in items if a["advisory"] == "CVE-2099-1001" and a["client_id"] == retail["id"])
    case = api.call("POST", "/cases", json={"title": "Acme Insight Agent RCE: Contoso storefront", "assessment_ids": [target["id"]],
                                            "description": "Synthetic demo case: advisory matches the Insight Agent recorded on the storefront API repository."})
    v = case["version"]
    for to in ("triage", "investigating"):
        v = api.call("POST", f"/cases/{case['id']}/transition", json={"to": to, "version": v})["version"]
    api.call("POST", f"/cases/{case['id']}/notes", json={"body": "Version 4.1.0 is inside the affected range (< 4.2.1). Checking whether telemetry endpoint is internet reachable.", "visibility": "internal"})
    api.call("POST", f"/cases/{case['id']}/notes", json={"body": "We are verifying the deployed version and will report back shortly.", "visibility": "customer"})
    api.call("POST", f"/cases/{case['id']}/evidence", json={"kind": "url", "title": "Vendor advisory (synthetic)", "source_name": "Acme PSIRT (synthetic)",
                                                            "source_url": "https://example.com/synthetic/CVE-2099-1001", "excerpt": "Insight Agent before 4.2.1 is affected.", "assessment_id": target["id"]})
    t1 = api.call("POST", f"/cases/{case['id']}/tasks", json={"title": "Verify deployed Insight Agent version on storefront-api", "assignee_id": api.call("GET", "/auth/me")["user"]["id"], "priority": "high"})
    api.call("PATCH", f"/tasks/{t1['id']}", json={"status": "done", "completion_notes": "Confirmed 4.1.0 in production lockfile; upgrade scheduled."})
    api.call("POST", f"/cases/{case['id']}/tasks", json={"title": "Upgrade Insight Agent to 4.2.1 and confirm", "priority": "high"})
    api.call("POST", f"/cases/{case['id']}/reports", json={"kind": "technical"})

    if args.with_rival:
        # A second, unrelated organization so tenant isolation can be demonstrated side by side.
        rival = Client(args.base_url, args.origin)
        r = rival.auth("/auth/register", {"email": "rival.owner@example.com", "password": password, "organization_name": "Rival MSP (DEMO)", "display_name": "Rival Owner"})
        if r.status_code < 400:
            rival.call("POST", "/clients", json={"name": "Rival Client (synthetic)", "industry": "finance"})
            rival.call("POST", "/vendors", json={"name": "Rival Vendor (synthetic)", "website": "rival-vendor.example.com"})
            print("  rival   rival.owner@example.com (separate organization)")
    print("\nSynthetic demo organization created:", DEMO_ORG)
    print(f"  owner   {owner_email}\n  analyst {analyst_email}\n  viewer  {viewer_email}")
    print(f"  password {password}\n  (shown once; all demo data is synthetic)")


if __name__ == "__main__":
    main()
