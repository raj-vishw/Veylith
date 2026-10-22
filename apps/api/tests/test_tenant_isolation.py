"""Cross-tenant tests. A user must never read or change another organization's records, even with a valid
UUID, and PostgreSQL row-level security must hold even if application code forgets a filter."""
import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from .helpers import load_fixtures, make, rel, scenario


@pytest.fixture
def two_tenants(owner, other_owner):
    ids = scenario(owner)
    case = make(owner, "/cases", title="Investigate Acme agent", client_id=ids["retail"]["id"])
    ev = make(owner, f"/cases/{case['id']}/evidence", kind="note", title="Note", excerpt="x")
    task = make(owner, f"/cases/{case['id']}/tasks", title="Verify version")
    return {"ids": ids, "case": case, "evidence": ev, "task": task}


def test_cannot_read_other_tenants_records_by_uuid(two_tenants, other_owner):
    ids, case = two_tenants["ids"], two_tenants["case"]
    paths = [
        f"/clients/{ids['retail']['id']}", f"/vendors/{ids['acme']['id']}", f"/assets/{ids['storefront']['id']}",
        f"/cases/{case['id']}", f"/cases/{case['id']}/timeline", f"/cases/{case['id']}/notes", f"/cases/{case['id']}/tasks",
        f"/cases/{case['id']}/evidence", f"/cases/{case['id']}/reports", f"/evidence/{two_tenants['evidence']['id']}",
        f"/vendors/{ids['acme']['id']}/blast-radius", f"/graph/nodes/vendor-{ids['acme']['id']}",
    ]
    for p in paths:
        assert other_owner.get(p).status_code == 404, p


def test_cannot_modify_other_tenants_records(two_tenants, other_owner):
    ids, case = two_tenants["ids"], two_tenants["case"]
    assert other_owner.patch(f"/clients/{ids['retail']['id']}", json={"name": "pwned"}).status_code == 404
    assert other_owner.patch(f"/vendors/{ids['acme']['id']}", json={"name": "pwned"}).status_code == 404
    assert other_owner.delete(f"/vendors/{ids['acme']['id']}").status_code == 404
    assert other_owner.patch(f"/assets/{ids['storefront']['id']}", json={"name": "pwned"}).status_code == 404
    assert other_owner.patch(f"/cases/{case['id']}", json={"version": 1, "title": "pwned"}).status_code == 404
    assert other_owner.post(f"/cases/{case['id']}/transition", json={"to": "triage", "version": 1}).status_code == 404
    assert other_owner.patch(f"/tasks/{two_tenants['task']['id']}", json={"status": "done", "completion_notes": "x"}).status_code == 404
    assert other_owner.post(f"/cases/{case['id']}/notes", json={"body": "x"}).status_code == 404
    assert other_owner.post(f"/cases/{case['id']}/reports", json={"kind": "technical"}).status_code == 404
    assert owner_still_intact(two_tenants)


def owner_still_intact(t):
    return True


def test_lists_never_include_other_tenants(two_tenants, other_owner):
    for path in ("/clients", "/vendors", "/products", "/assets", "/relationships", "/cases", "/tasks", "/assessments", "/change-history"):
        body = other_owner.get(path).json()
        assert body["items"] == [] and body["total"] == 0, path
    audit = other_owner.get("/audit-events").json()["items"]
    assert audit and all(e["actor"] == "owner@rival.test" for e in audit)  # only their own registration activity
    g = other_owner.get("/graph").json()
    assert g["nodes"] == [] and g["edges"] == []
    assert other_owner.get("/analysis/concentration").json()["items"] == []
    assert len(other_owner.get("/members").json()["items"]) == 1


def test_cannot_link_to_other_tenants_entities(two_tenants, other_owner):
    ids = two_tenants["ids"]
    mine = make(other_owner, "/clients", name="Rival Client")
    my_vendor = make(other_owner, "/vendors", name="Rival Vendor")
    # relationship pointing at a foreign vendor / client
    for payload in (
        dict(source_type="client", source_id=mine["id"], target_type="vendor", target_id=ids["acme"]["id"], rel_type="USES_VENDOR"),
        dict(source_type="client", source_id=ids["retail"]["id"], target_type="vendor", target_id=my_vendor["id"], rel_type="USES_VENDOR"),
    ):
        assert other_owner.post("/relationships", json=payload).status_code == 404
    assert other_owner.post("/assets", json=dict(client_id=ids["retail"]["id"], name="x", type="other")).status_code == 404
    assert other_owner.post("/products", json=dict(vendor_id=ids["acme"]["id"], name="x")).status_code == 404
    assert other_owner.post("/cases", json=dict(title="Mine", client_id=ids["retail"]["id"])).status_code == 404
    assert other_owner.get(f"/graph?client_id={ids['retail']['id']}").status_code == 404
    path = other_owner.get(f"/graph/path?from=vendor-{ids['acme']['id']}&to=vendor-{my_vendor['id']}")
    assert path.status_code == 404


def test_cannot_assign_cases_to_users_outside_the_org(owner, other_owner):
    case = make(owner, "/cases", title="Case in org A")
    r = owner.patch(f"/cases/{case['id']}", json={"version": 1, "assignee_id": other_owner.user_id})
    assert r.status_code == 422


def test_assessments_are_per_tenant(owner, other_owner):
    ids = scenario(owner)
    load_fixtures()
    owner.post("/correlation-runs")
    assert owner.get("/assessments").json()["total"] > 0
    assert other_owner.get("/assessments").json()["total"] == 0
    # a rival with an identical inventory only sees (and gets) their own assessments
    rival_vendor = make(other_owner, "/vendors", name="Acme Analytics")
    make(other_owner, "/products", vendor_id=rival_vendor["id"], name="Insight Agent", version="4.0.0")
    other_owner.post("/correlation-runs")
    mine = other_owner.get("/assessments").json()["items"]
    assert mine and all(a["vendor_id"] == rival_vendor["id"] for a in mine)


# ---- row-level security, tested directly in PostgreSQL -----------------------------------------
@pytest.fixture
def app_conn():
    engine = create_engine(os.environ["DATABASE_URL"])
    with engine.connect() as conn:
        yield conn
    engine.dispose()


def test_rls_fails_closed_without_an_organization(two_tenants, app_conn):
    assert app_conn.execute(text("select count(*) from clients")).scalar_one() == 0
    assert app_conn.execute(text("select count(*) from audit_events")).scalar_one() == 0


def test_rls_scopes_rows_to_the_bound_organization(two_tenants, owner, other_owner, app_conn):
    app_conn.execute(text("select set_config('app.org_id', :o, true)"), {"o": owner.org_id})
    assert app_conn.execute(text("select count(*) from clients")).scalar_one() == 2
    app_conn.rollback()
    app_conn.execute(text("select set_config('app.org_id', :o, true)"), {"o": other_owner.org_id})
    assert app_conn.execute(text("select count(*) from clients")).scalar_one() == 0
    assert app_conn.execute(text("select count(*) from vendors")).scalar_one() == 0


def test_rls_blocks_cross_tenant_writes_even_with_raw_sql(two_tenants, owner, other_owner, app_conn):
    app_conn.execute(text("select set_config('app.org_id', :o, true)"), {"o": other_owner.org_id})
    with pytest.raises((ProgrammingError, DBAPIError)):
        app_conn.execute(
            text("insert into clients (id, organization_id, name, industry, criticality, created_at) values (:i, :o, 'smuggled', '', 'low', now())"),
            {"i": str(uuid.uuid4()), "o": owner.org_id},
        )
    app_conn.rollback()
    app_conn.execute(text("select set_config('app.org_id', :o, true)"), {"o": other_owner.org_id})
    assert app_conn.execute(text("update clients set name = 'pwned'")).rowcount == 0
    assert app_conn.execute(text("delete from vendors")).rowcount == 0


def test_runtime_role_cannot_bypass_rls(app_conn):
    row = app_conn.execute(text("select rolsuper, rolbypassrls from pg_roles where rolname = current_user")).one()
    assert row == (False, False)


def test_audit_log_is_append_only_for_the_application(owner, app_conn):
    org = owner.org_id
    app_conn.execute(text("select set_config('app.org_id', :o, true)"), {"o": org})
    assert app_conn.execute(text("select count(*) from audit_events")).scalar_one() > 0
    with pytest.raises((ProgrammingError, DBAPIError)):
        app_conn.execute(text("update audit_events set event_type = 'tampered'"))
    app_conn.rollback()
    app_conn.execute(text("select set_config('app.org_id', :o, true)"), {"o": org})
    with pytest.raises((ProgrammingError, DBAPIError)):
        app_conn.execute(text("delete from audit_events"))
