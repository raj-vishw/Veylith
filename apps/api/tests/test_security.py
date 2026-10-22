"""Regression tests for the Day-22 security review. Each test names the risk it guards against."""
import json
import logging

import pytest

from .helpers import make, scenario


def test_security_headers_on_every_response(owner):
    for path in ("/clients", "/auth/me"):
        h = owner.get(path).headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "same-origin" and h["cache-control"] == "no-store"
    assert owner.http.get("/health").headers["x-request-id"]


def test_no_cors_is_enabled(owner):
    r = owner.http.options("/api/v1/clients", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in r.headers
    assert "access-control-allow-origin" not in owner.get("/clients", headers={"Origin": "https://evil.example"}).headers


def test_api_docs_are_hidden_in_production():
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app

    prod = TestClient(create_app(Settings(environment="production")))
    assert prod.get("/api/v1/docs").status_code == 404 and prod.get("/api/v1/openapi.json").status_code == 404
    dev = TestClient(create_app(Settings(environment="development")))
    assert dev.get("/api/v1/docs").status_code == 200


def test_validation_errors_do_not_echo_submitted_values(make_api):
    secret = "Sup3r-Secret-Password!"
    r = make_api().post("/auth/login", json={"email": "not-an-email", "password": secret})
    assert r.status_code == 422 and secret not in r.text
    r = make_api().post("/auth/register", json={"email": "a@example.test", "password": "x", "organization_name": "O"})
    assert r.status_code == 422


def test_unhandled_errors_are_generic_and_carry_a_request_id(owner, monkeypatch):
    from app.routers import inventory

    def boom(*a, **k):
        raise RuntimeError("secret internal detail: db password is hunter2")

    monkeypatch.setattr(inventory, "_client", boom)
    r = owner.post("/clients", json={"name": "x"})
    assert r.status_code == 500
    assert "hunter2" not in r.text and "RuntimeError" not in r.text and r.json()["request_id"]


def test_passwords_and_tokens_never_reach_the_logs(make_api, caplog):
    caplog.set_level(logging.DEBUG)
    api = make_api()
    api.register("logs@example.test", password="Log-Check-Passw0rd!")
    api.login("logs@example.test", password="Log-Check-Passw0rd!")
    token = api.http.cookies.get("veylith_session")
    api.post("/auth/change-password", json={"current_password": "Log-Check-Passw0rd!", "new_password": "Another-Passw0rd-123"})
    logged = "\n".join(r.getMessage() for r in caplog.records) + "\n".join(json.dumps(getattr(r, "__dict__", {}), default=str) for r in caplog.records)
    for secret in ("Log-Check-Passw0rd!", "Another-Passw0rd-123", token, api.csrf):
        assert secret not in logged


def test_request_logs_contain_the_path_but_not_the_query_string(owner, caplog):
    caplog.set_level(logging.INFO)
    owner.get("/vendors?q=confidential-customer-name")
    lines = " ".join(r.getMessage() + str(r.__dict__.get("path", "")) for r in caplog.records if r.name.startswith("veylith"))
    assert "/api/v1/vendors" in lines and "confidential-customer-name" not in lines


def test_sql_injection_payloads_are_inert(owner):
    scenario(owner)
    payloads = ["' OR '1'='1", "'; DROP TABLE vendors; --", "%' UNION SELECT password_hash FROM users --", "\\"]
    for p in payloads:
        for path in ("/vendors?q=", "/clients?q=", "/assets?q=", "/advisories?q=", "/cases?q="):
            r = owner.get(path + p)
            assert r.status_code == 200, (path, p)
    assert owner.get("/vendors").json()["total"] == 4  # the data is untouched
    v = make(owner, "/vendors", name="Robert'); DROP TABLE users;--")
    assert owner.get(f"/vendors/{v['id']}").json()["name"] == "Robert'); DROP TABLE users;--"


def test_oversized_and_malformed_bodies_are_rejected(owner):
    assert owner.post("/clients", json={"name": "x" * 5000}).status_code == 422
    assert owner.post("/vendors", json={"name": "ok", "notes": "n" * 20000}).status_code == 422
    assert owner.post("/clients", content=b"{not json", headers={"Content-Type": "application/json"}).status_code == 422
    assert owner.post("/clients", json=["a", "list"]).status_code == 422
    assert owner.get("/clients/not-a-uuid").status_code == 422


def test_unknown_fields_cannot_set_privileged_columns(owner, other_owner):
    r = owner.post("/clients", json={"name": "Mass assignment", "organization_id": other_owner.org_id, "id": "00000000-0000-0000-0000-000000000001", "archived_at": "2000-01-01T00:00:00Z"})
    assert r.status_code == 201
    body = r.json()
    assert body["id"] != "00000000-0000-0000-0000-000000000001" and body["archived_at"] is None
    assert other_owner.get("/clients").json()["total"] == 0  # not created in the other tenant


def test_no_endpoint_fetches_user_supplied_urls():
    """SSRF guard: ingestion endpoints take only an enum of fixed sources, never a URL."""
    from app.routers.intelligence import IngestionIn

    for bad in ("http://169.254.169.254/latest/meta-data", "https://evil.example/feed.json", "file:///etc/passwd"):
        with pytest.raises(Exception):
            IngestionIn(source=bad)
    from app.config import get_settings

    s = get_settings()
    assert s.nvd_base_url.startswith("https://services.nvd.nist.gov/") and s.kev_url.startswith("https://www.cisa.gov/")


def test_session_cookie_is_not_readable_by_scripts_and_is_scoped(make_api):
    api = make_api()
    header = api.register("c@example.test").headers["set-cookie"].lower()
    assert "httponly" in header and "path=/" in header and "domain=" not in header


def test_secure_cookie_flag_follows_configuration(make_api, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "cookie_secure", True)
    header = make_api().register("s@example.test").headers["set-cookie"].lower()
    assert "secure" in header


def test_responses_never_contain_password_hashes_or_session_secrets(owner, analyst):
    for path in ("/members", "/auth/me", "/organization", "/audit-events"):
        text = owner.get(path).text
        assert "argon2" not in text and "password_hash" not in text and "token_hash" not in text


def test_object_ids_from_another_org_look_like_missing_objects(owner, other_owner):
    c = make(owner, "/clients", name="Mine")
    import uuid

    missing = other_owner.get(f"/clients/{uuid.uuid4()}")
    foreign = other_owner.get(f"/clients/{c['id']}")
    assert missing.status_code == foreign.status_code == 404
    assert missing.json()["detail"] == foreign.json()["detail"]  # indistinguishable: no existence oracle
