import io

from .helpers import make, rel, scenario


def csv_file(text):
    return {"file": ("vendors.csv", io.BytesIO(text.encode()), "text/csv")}


def test_client_crud_and_archive(owner):
    c = make(owner, "/clients", name="Retail Co", industry="retail")
    assert owner.patch(f"/clients/{c['id']}", json={"criticality": "critical"}).json()["criticality"] == "critical"
    assert owner.get("/clients?q=retail").json()["total"] == 1
    owner.post(f"/clients/{c['id']}/archive")
    assert owner.get("/clients").json()["total"] == 0
    assert owner.get("/clients?include_archived=true").json()["total"] == 1
    assert owner.post(f"/clients/{c['id']}/restore").json()["archived_at"] is None


def test_vendor_crud_filters_and_domain_normalisation(owner):
    v = make(owner, "/vendors", name="Acme", website="HTTPS://www.Acme-Analytics.com/pricing?x=1", category="analytics", criticality="high")
    assert v["domain"] == "acme-analytics.com" and v["website"] == "https://acme-analytics.com"
    assert owner.post("/vendors", json={"name": "Bad", "website": "javascript:alert(1)"}).status_code == 422
    assert owner.post("/vendors", json={"name": "Bad", "website": "not a domain"}).status_code == 422
    assert owner.get("/vendors?criticality=high").json()["total"] == 1
    assert owner.get("/vendors?q=analytics").json()["total"] == 1
    assert owner.get("/vendors?q=zzz").json()["total"] == 0
    assert owner.post("/vendors", json={"name": "ACME"}).status_code == 409  # duplicate name
    assert owner.post("/vendors", json={"name": "Other", "website": "acme-analytics.com"}).status_code == 409  # duplicate domain
    assert owner.patch(f"/vendors/{v['id']}", json={"access_level": "admin"}).json()["access_level"] == "admin"
    assert owner.delete(f"/vendors/{v['id']}").status_code == 204
    assert owner.get(f"/vendors/{v['id']}").status_code == 404
    assert owner.get("/vendors").json()["total"] == 0


def test_input_validation(owner):
    assert owner.post("/vendors", json={"name": "x", "criticality": "extreme"}).status_code == 422
    assert owner.post("/vendors", json={"name": ""}).status_code == 422
    assert owner.post("/assets", json={"client_id": "not-a-uuid", "name": "x", "type": "other"}).status_code == 422
    assert owner.post("/products", json={"vendor_id": make(owner, "/vendors", name="V")["id"], "name": "P", "cpe": "garbage"}).status_code == 422
    assert owner.get("/vendors?limit=100000").json()["limit"] == 100  # page size is capped


def test_csv_import_preview_then_commit(owner):
    make(owner, "/vendors", name="Existing Vendor", website="existing.io")
    data = (
        "name,website,category,criticality,access_level\n"
        "Acme Analytics,https://www.acme.com/x,analytics,high,read\n"
        "Existing Vendor,other.com,x,low,none\n"            # duplicate name
        "Dupe Domain,existing.io,x,low,none\n"              # duplicate domain
        "Acme Analytics,acme2.com,,low,none\n"              # duplicate within the file
        ",nothing.com,,low,none\n"                          # missing name
        "Bad Site,not a url,,low,none\n"                    # bad domain
        "Bad Level,ok.com,,extreme,none\n"                  # bad criticality
        "Good Two,good.org,,medium,write\n"
    )
    preview = owner.post("/vendors/import?dry_run=true", files=csv_file(data)).json()
    assert preview["dry_run"] is True
    assert [a["name"] for a in preview["accepted"]] == ["Acme Analytics", "Good Two"]
    assert preview["accepted"][0]["domain"] == "acme.com"
    assert len(preview["duplicates"]) == 3 and len(preview["rejected"]) == 3
    assert all(r["errors"] for r in preview["rejected"])
    assert owner.get("/vendors").json()["total"] == 1  # preview changed nothing

    done = owner.post("/vendors/import?dry_run=false", files=csv_file(data)).json()
    assert len(done["accepted"]) == 2 and owner.get("/vendors").json()["total"] == 3
    again = owner.post("/vendors/import?dry_run=false", files=csv_file(data)).json()
    assert again["accepted"] == [] and owner.get("/vendors").json()["total"] == 3  # re-import is safe
    types = [e["event_type"] for e in owner.get("/audit-events").json()["items"]]
    assert "vendor.csv_imported" in types


def test_csv_import_guards(owner, viewer):
    assert owner.post("/vendors/import", files=csv_file("title,site\nx,y\n")).status_code == 422  # no name column
    assert owner.post("/vendors/import", files={"file": ("v.csv", io.BytesIO(b"\xff\xfe\x00bad"), "text/csv")}).status_code == 422
    assert owner.post("/vendors/import", files=csv_file("name\n" + "a" * 2_000_000)).status_code == 413
    assert viewer.post("/vendors/import", files=csv_file("name\nx\n")).status_code == 403
    csv_injection = owner.post("/vendors/import?dry_run=true", files=csv_file('name\n"=HYPERLINK(""http://evil"")"\n')).json()
    assert csv_injection["accepted"][0]["name"].startswith("=")  # stored as inert text; the UI escapes it


def test_csv_import_is_rate_limited(owner):
    codes = [owner.post("/vendors/import", files=csv_file("name\nx\n")).status_code for _ in range(14)]
    assert 429 in codes


def test_relationship_rules(owner):
    ids = scenario(owner)
    # a vendor being used by a client does not mean it can reach their systems: types are explicit and validated
    bad = owner.post("/relationships", json=dict(source_type="vendor", source_id=ids["acme"]["id"], target_type="client", target_id=ids["retail"]["id"], rel_type="USES_VENDOR"))
    assert bad.status_code == 422
    dup = owner.post("/relationships", json=dict(source_type="client", source_id=ids["retail"]["id"], target_type="vendor", target_id=ids["acme"]["id"], rel_type="USES_VENDOR"))
    assert dup.status_code == 409
    ok = rel(owner, "vendor", ids["acme"]["id"], "HAS_ACCESS_TO", "asset", ids["storefront"]["id"], access_scope="read:repo", evidence="OAuth app list", confidence="high")
    assert ok["verification_status"] == "unverified" and ok["access_scope"] == "read:repo"
    patched = owner.patch(f"/relationships/{ok['id']}", json={"verification_status": "verified", "verification_method": "document"}).json()
    assert patched["verified_at"] is not None
    assert owner.delete(f"/relationships/{ok['id']}").status_code == 204
    types = [e["event_type"] for e in owner.get("/audit-events").json()["items"]]
    assert "relationship.created" in types and "relationship.deleted" in types


def test_change_history_records_inventory_changes(owner):
    v = make(owner, "/vendors", name="Acme")
    owner.patch(f"/vendors/{v['id']}", json={"access_level": "admin"})
    history = owner.get(f"/change-history?object_type=vendor&object_id={v['id']}").json()["items"]
    assert [h["action"] for h in history] == ["updated", "created"]
    assert history[0]["changes"]["access_level"] == {"from": "none", "to": "admin"}


def test_audit_events_are_server_generated_with_actor(owner):
    make(owner, "/clients", name="Audit Me")
    ev = next(e for e in owner.get("/audit-events").json()["items"] if e["event_type"] == "client.created")
    assert ev["actor"] == "owner@msp.test" and ev["metadata"]["name"] == "Audit Me" and ev["occurred_at"]
