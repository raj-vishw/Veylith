from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from .helpers import TEST_PASSWORD


def test_unauthenticated_requests_are_rejected(make_api):
    api = make_api()
    for path in ("/auth/me", "/clients", "/vendors", "/assessments", "/cases", "/audit-events", "/members"):
        assert api.get(path).status_code == 401, path


def test_register_login_logout(make_api):
    api = make_api()
    r = api.register("a@example.test")
    assert r.status_code == 201 and r.json()["role"] == "owner"
    assert api.get("/auth/me").json()["user"]["email"] == "a@example.test"

    assert api.post("/auth/logout").status_code == 204
    assert api.get("/auth/me").status_code == 401  # logout invalidates the session server-side

    again = make_api()
    assert again.login("a@example.test").status_code == 200


def test_logout_invalidates_stolen_cookie(make_api):
    api = make_api()
    api.register("a@example.test")
    cookie = api.http.cookies.get("veylith_session")
    csrf = api.csrf
    api.post("/auth/logout")
    thief = make_api()
    thief.http.cookies.set("veylith_session", cookie)
    thief.csrf = csrf
    assert thief.get("/auth/me").status_code == 401


def test_login_errors_are_generic(make_api):
    api = make_api()
    api.register("real@example.test")
    wrong_pw = make_api().login("real@example.test", password="not-the-password")
    unknown = make_api().login("nobody@example.test")
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


def test_password_is_hashed_with_argon2_and_never_returned(make_api, owner_engine):
    api = make_api()
    r = api.register("a@example.test")
    assert "password" not in r.text
    with owner_engine.connect() as conn:
        stored = conn.execute(text("select password_hash from users")).scalar_one()
    assert stored.startswith("$argon2id$")


def test_session_token_is_stored_hashed(make_api, owner_engine):
    api = make_api()
    api.register("a@example.test")
    cookie = api.http.cookies.get("veylith_session")
    with owner_engine.connect() as conn:
        hashes = [r[0] for r in conn.execute(text("select token_hash from sessions"))]
    assert cookie not in hashes and len(hashes[0]) == 64


def test_weak_password_rejected_without_echoing_it(make_api):
    r = make_api().post("/auth/register", json={"email": "a@example.test", "password": "short", "organization_name": "Org"})
    assert r.status_code == 422 and "short" not in r.text


def test_csrf_token_required_for_state_changes(owner):
    owner.csrf = ""
    assert owner.post("/clients", json={"name": "X"}).status_code == 403
    owner.csrf = "wrong"
    assert owner.post("/clients", json={"name": "X"}).status_code == 403
    assert owner.get("/clients").status_code == 200  # safe methods do not need it


def test_untrusted_origin_rejected(owner):
    r = owner.post("/clients", json={"name": "X"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    ok = owner.post("/clients", json={"name": "X"}, headers={"Origin": "http://localhost:3000"})
    assert ok.status_code == 201


def test_cookie_flags(make_api):
    api = make_api()
    r = api.register("a@example.test")
    header = r.headers["set-cookie"].lower()
    assert "httponly" in header and "samesite=lax" in header


def test_expired_session_rejected(owner, owner_engine):
    with owner_engine.begin() as conn:
        conn.execute(text("update sessions set expires_at = :t"), {"t": datetime.now(timezone.utc) - timedelta(minutes=1)})
    assert owner.get("/auth/me").status_code == 401


def test_idle_session_rejected(owner, owner_engine):
    with owner_engine.begin() as conn:
        conn.execute(text("update sessions set last_seen_at = :t"), {"t": datetime.now(timezone.utc) - timedelta(hours=5)})
    assert owner.get("/auth/me").status_code == 401


def test_login_rate_limited(make_api):
    api = make_api()
    api.register("a@example.test")
    codes = [make_api().login("a@example.test", password="bad-password-1").status_code for _ in range(14)]
    assert 429 in codes


def test_logout_all_revokes_every_session(make_api):
    a, b = make_api(), make_api()
    a.register("a@example.test")
    b.login("a@example.test")
    assert a.post("/auth/logout-all").status_code == 204
    assert b.get("/auth/me").status_code == 401


# ---- roles ------------------------------------------------------------------
def test_analyst_cannot_manage_members_or_settings(analyst, owner):
    assert analyst.get("/members").status_code == 200
    assert analyst.post("/members", json={"email": "x@msp.test", "password": TEST_PASSWORD, "role": "viewer"}).status_code == 403
    assert analyst.patch(f"/members/{owner.user_id}", json={"role": "viewer"}).status_code == 403
    assert analyst.patch("/organization", json={"name": "Hijacked"}).status_code == 403
    assert analyst.delete(f"/members/{owner.user_id}").status_code == 403


def test_viewer_is_read_only(viewer, owner):
    assert viewer.get("/clients").status_code == 200
    assert viewer.post("/clients", json={"name": "Nope"}).status_code == 403
    assert viewer.post("/vendors", json={"name": "Nope"}).status_code == 403
    assert viewer.get("/audit-events").status_code == 403  # audit history is for analysts and owners


def test_role_change_applies_immediately(owner, analyst):
    assert analyst.post("/clients", json={"name": "Before"}).status_code == 201
    assert owner.patch(f"/members/{analyst.user_id}", json={"role": "viewer"}).status_code == 200
    assert analyst.post("/clients", json={"name": "After"}).status_code == 401  # privilege change signs the user out


def test_removed_member_loses_access(owner, analyst):
    assert owner.delete(f"/members/{analyst.user_id}").status_code == 204
    assert analyst.get("/clients").status_code == 401


def test_last_owner_cannot_be_demoted_or_removed(owner):
    assert owner.patch(f"/members/{owner.user_id}", json={"role": "viewer"}).status_code == 409
    assert owner.delete(f"/members/{owner.user_id}").status_code == 409


def test_switching_org_requires_membership(owner, other_owner):
    assert owner.post("/auth/switch-org", json={"organization_id": other_owner.org_id}).status_code == 404
    assert owner.get("/auth/me").json()["organization"]["id"] == owner.org_id


def test_audit_trail_records_auth_and_membership(owner, analyst):
    types = [e["event_type"] for e in owner.get("/audit-events").json()["items"]]
    assert "auth.registered" in types and "member.added" in types and "auth.login" in types
    assert TEST_PASSWORD not in owner.get("/audit-events").text


def test_change_password_revokes_other_sessions(make_api):
    a, b = make_api(), make_api()
    a.register("a@example.test")
    b.login("a@example.test")
    assert a.post("/auth/change-password", json={"current_password": "wrong-password-1", "new_password": "a-brand-new-password"}).status_code == 403
    assert a.post("/auth/change-password", json={"current_password": TEST_PASSWORD, "new_password": "short"}).status_code == 422
    assert a.post("/auth/change-password", json={"current_password": TEST_PASSWORD, "new_password": "a-brand-new-password"}).status_code == 204
    assert a.get("/auth/me").status_code == 200  # the session that changed it stays signed in
    assert b.get("/auth/me").status_code == 401  # other sessions are signed out
    assert make_api().login("a@example.test").status_code == 401  # the old password no longer works
    assert make_api().login("a@example.test", password="a-brand-new-password").status_code == 200
    types = [e["event_type"] for e in a.get("/audit-events").json()["items"]]
    assert "auth.password_changed" in types and "a-brand-new-password" not in a.get("/audit-events").text


def test_cross_site_login_and_registration_are_rejected(make_api):
    api = make_api()
    api.register("a@example.test")
    evil = {"Origin": "https://evil.example"}
    assert make_api().post("/auth/login", json={"email": "a@example.test", "password": TEST_PASSWORD}, headers=evil).status_code == 403
    assert make_api().post("/auth/register", json={"email": "b@example.test", "password": TEST_PASSWORD, "organization_name": "Valid Org"}, headers=evil).status_code == 403
    ok = make_api().post("/auth/login", json={"email": "a@example.test", "password": TEST_PASSWORD}, headers={"Origin": "http://localhost:3000"})
    assert ok.status_code == 200


def test_registration_can_be_disabled(make_api, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "allow_registration", False)
    assert make_api().register("a@example.test").status_code == 403


def test_concurrent_duplicate_registration_is_a_clean_conflict(make_api):
    first = make_api()
    assert first.register("dup@example.test").status_code == 201
    assert make_api().register("dup@example.test").status_code == 409


def test_viewer_can_download_ready_reports_but_not_evidence(owner, viewer, monkeypatch):
    from app.services import reports

    monkeypatch.setattr(reports, "render_pdf", lambda html: b"%PDF-1.7 x")
    case = owner.post("/cases", json={"title": "Viewer download"}).json()
    owner.post(f"/cases/{case['id']}/reports", json={"kind": "executive"})
    rid = owner.get(f"/cases/{case['id']}/reports").json()["items"][0]["id"]
    assert viewer.get(f"/reports/{rid}/download").status_code == 200
    assert viewer.post(f"/cases/{case['id']}/reports", json={}).status_code == 403


def test_analyst_audit_view_is_limited(owner, analyst):
    types = {e["event_type"] for e in analyst.get("/audit-events").json()["items"]}
    assert not any(t.startswith(("auth.", "member.", "organization.")) for t in types)
    assert any(t.startswith("auth.") for t in {e["event_type"] for e in owner.get("/audit-events").json()["items"]})


def test_role_change_forces_reauthentication(owner, analyst):
    assert owner.patch(f"/members/{analyst.user_id}", json={"role": "viewer"}).status_code == 200
    assert analyst.get("/auth/me").status_code == 401


def test_disabled_account_cannot_log_in_or_keep_a_session(owner, analyst, owner_engine):
    from sqlalchemy import text

    with owner_engine.begin() as conn:
        conn.execute(text("update users set status = 'disabled' where email = 'analyst@msp.test'"))
    assert analyst.get("/auth/me").status_code == 401
    from tests.conftest import Api

    assert Api().login("analyst@msp.test").status_code == 401


def test_non_json_bodies_are_rejected_and_csrf_endpoint_works(owner):
    assert owner.post("/clients", content=b'{"name":"x"}', headers={"Content-Type": "text/plain"}).status_code in (415, 422)
    assert owner.get("/auth/csrf").json()["csrf_token"] == owner.csrf
    assert owner.http.get("/health/live").status_code == 200


def test_pooled_connections_never_carry_a_previous_tenants_context(owner, other_owner):
    from app.db import org_session
    from app.models import Client
    from sqlalchemy import select
    import uuid

    owner.post("/clients", json={"name": "A-only"})
    for _ in range(5):  # alternate tenants over the same small pool
        with org_session(uuid.UUID(owner.org_id)) as db:
            assert [c.name for c in db.scalars(select(Client))] == ["A-only"]
        with org_session(uuid.UUID(other_owner.org_id)) as db:
            assert list(db.scalars(select(Client))) == []


def test_relationship_by_id(owner):
    from .helpers import make, rel

    c, v = make(owner, "/clients", name="C"), make(owner, "/vendors", name="V")
    r = rel(owner, "client", c["id"], "USES_VENDOR", "vendor", v["id"])
    assert owner.get(f"/relationships/{r['id']}").json()["rel_type"] == "USES_VENDOR"
