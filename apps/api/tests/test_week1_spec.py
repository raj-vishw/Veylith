"""Week 1 specification items: statuses, membership history, organization creation, verification method, field coverage."""
from sqlalchemy import text

from .helpers import make, rel


def test_database_enforces_status_and_type_values(owner_engine, owner):
    import pytest
    from sqlalchemy.exc import IntegrityError

    for statement in (
        "update memberships set status = 'maybe'",
        "update memberships set role = 'root'",
        "update users set status = 'zombie'",
        "update organizations set status = 'gone'",
    ):
        with pytest.raises(IntegrityError), owner_engine.begin() as conn:
            conn.execute(text(statement))


def test_database_rejects_unknown_relationship_and_asset_types(owner_engine, owner):
    import pytest
    from sqlalchemy.exc import IntegrityError

    c = make(owner, "/clients", name="C")
    make(owner, "/assets", client_id=c["id"], name="a", type="saas_application")
    with pytest.raises(IntegrityError), owner_engine.begin() as conn:
        conn.execute(text("update assets set type = 'toaster'"))


def test_removed_member_is_revoked_not_deleted_and_can_be_readmitted(owner, analyst, owner_engine):
    assert owner.delete(f"/members/{analyst.user_id}").status_code == 204
    with owner_engine.connect() as conn:
        row = conn.execute(text("select m.status, m.role from memberships m join users u on u.id = m.user_id where u.email = 'analyst@msp.test'")).one()
    assert row == ("revoked", "analyst")
    assert analyst.get("/clients").status_code == 401  # an expired/revoked membership gives no access
    listed = {m["email"]: m["status"] for m in owner.get("/members").json()["items"]}
    assert listed["analyst@msp.test"] == "revoked"
    from tests.conftest import Api

    assert Api().login("analyst@msp.test").status_code == 401  # cannot sign in to an org they were removed from
    readded = owner.post("/members", json={"email": "analyst@msp.test", "role": "viewer"})
    assert readded.status_code == 201 and readded.json()["status"] == "active" and readded.json()["role"] == "viewer"
    api = Api()
    assert api.login("analyst@msp.test").status_code == 200
    assert "member.revoked" in [e["event_type"] for e in owner.get("/audit-events").json()["items"]]


def test_a_user_can_create_additional_organizations_and_switch(owner):
    r = owner.post("/organizations", json={"name": "Second Workspace"})
    assert r.status_code == 201 and r.json()["slug"] == "second-workspace"
    me = owner.get("/auth/me").json()
    assert {o["name"] for o in me["organizations"]} == {"Acme MSP", "Second Workspace"}
    owner.post("/auth/switch-org", json={"organization_id": r.json()["id"]})
    assert owner.get("/clients").json()["total"] == 0  # fresh workspace, nothing from the first one


def test_suspended_organization_blocks_access(owner, owner_engine):
    with owner_engine.begin() as conn:
        conn.execute(text("update organizations set status = 'suspended'"))
    assert owner.get("/clients").status_code == 401


def test_slug_can_be_changed_by_owner_only_and_must_be_unique(owner, other_owner, analyst):
    assert owner.patch("/organization", json={"slug": "acme-msp"}).json()["slug"] == "acme-msp"
    assert owner.patch("/organization", json={"slug": "Bad Slug!"}).status_code == 422
    other_slug = other_owner.get("/organization").json()["slug"]
    assert owner.patch("/organization", json={"slug": other_slug}).status_code == 409
    assert analyst.patch("/organization", json={"slug": "hijack"}).status_code == 403


def test_verified_relationships_require_a_verification_method(owner):
    c, v = make(owner, "/clients", name="C"), make(owner, "/vendors", name="V")
    body = dict(source_type="client", source_id=c["id"], target_type="vendor", target_id=v["id"], rel_type="USES_VENDOR")
    assert owner.post("/relationships", json={**body, "verification_status": "verified"}).status_code == 422
    made = owner.post("/relationships", json=body).json()
    assert owner.patch(f"/relationships/{made['id']}", json={"verification_status": "verified"}).status_code == 422
    ok = owner.patch(f"/relationships/{made['id']}", json={"verification_status": "verified", "verification_method": "vendor_confirmation"})
    assert ok.status_code == 200 and ok.json()["verified_at"] and ok.json()["verification_method"] == "vendor_confirmation"


def test_client_owner_notes_status_and_updated_at(owner):
    c = make(owner, "/clients", name="Fabrikam", owner="Platform team", notes="Renewal in Q3")
    assert c["owner"] == "Platform team" and c["notes"] == "Renewal in Q3" and c["status"] == "active"
    owner.post(f"/clients/{c['id']}/archive")
    assert owner.get(f"/clients/{c['id']}").json()["status"] == "archived"
    assert owner.get(f"/clients/{c['id']}").json()["updated_at"]


def test_asset_types_and_product_fields(owner):
    c = make(owner, "/clients", name="C")
    for t in ("repository", "cloud_resource", "saas_application", "business_application", "software_package", "production_service", "identity", "other"):
        a = make(owner, "/assets", client_id=c["id"], name=f"a-{t}", type=t, product_name="Nginx", product_version="1.25.3", source="scan", verification_status="verified")
        assert a["product_name"] == "Nginx" and a["product_version"] == "1.25.3" and a["verification_status"] == "verified" and a["source"] == "scan"
    assert owner.post("/assets", json={"client_id": c["id"], "name": "x", "type": "toaster"}).status_code == 422


def test_vendor_sorting_and_review_status_filter(owner):
    for n in ("Charlie", "alpha", "Bravo"):
        make(owner, "/vendors", name=n)
    owner.patch(f"/vendors/{make(owner, '/vendors', name='Delta')['id']}", json={"review_status": "reviewed"})
    assert [v["name"] for v in owner.get("/vendors?sort=name").json()["items"]][0] == "alpha"
    assert [v["name"] for v in owner.get("/vendors?sort=-name").json()["items"]][0] == "Delta"
    assert owner.get("/vendors?sort=updated").json()["items"][0]["name"] == "Delta"
    assert [v["name"] for v in owner.get("/vendors?review_status=reviewed").json()["items"]] == ["Delta"]
    assert owner.get("/vendors?sort=password").status_code == 422


def test_dashboard_inventory_counts_and_empty_state(owner):
    assert owner.get("/dashboard").json()["inventory"] == {"clients": 0, "vendors": 0, "assets": 0, "relationships": 0}
    c, v = make(owner, "/clients", name="C"), make(owner, "/vendors", name="V")
    make(owner, "/assets", client_id=c["id"], name="a", type="repository")
    rel(owner, "client", c["id"], "USES_VENDOR", "vendor", v["id"])
    assert owner.get("/dashboard").json()["inventory"] == {"clients": 1, "vendors": 1, "assets": 1, "relationships": 1}
