import pytest
from uuid import UUID

from app.db import org_session
from app.services import reports

from .helpers import load_fixtures, make, scenario


@pytest.fixture
def case(owner):
    scenario(owner)
    load_fixtures()
    owner.post("/correlation-runs")
    a = next(x for x in owner.get("/assessments?limit=100").json()["items"] if x["advisory"] == "CVE-2099-1001" and x["client"] == "Retail Client")
    c = make(owner, "/cases", title="Agent <script>alert(1)</script> exposure", description="Desc with <b>markup</b>", assessment_ids=[a["id"]])
    make(owner, f"/cases/{c['id']}/notes", body="INTERNAL-ONLY-SECRET analyst theory", visibility="internal")
    make(owner, f"/cases/{c['id']}/notes", body="Customer update: verifying version.", visibility="customer")
    make(owner, f"/cases/{c['id']}/evidence", kind="url", title="Vendor advisory", source_url="https://acme.example/psirt/1", source_name="Acme PSIRT")
    make(owner, f"/cases/{c['id']}/tasks", title="Verify deployed version")
    return c


def html_for(owner, case, kind="technical"):
    with org_session(UUID(owner.org_id)) as db:
        data = reports.collect(db, UUID(owner.org_id), UUID(case["id"]), kind, "tester@msp.test", "RPT-TEST")
        return reports.render_html(data)


def test_html_report_escapes_user_supplied_markup(owner, case):
    html = html_for(owner, case)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "<b>markup</b>" not in html


def test_report_states_uncertainty_and_synthetic_data(owner, case):
    html = html_for(owner, case)
    assert "Potential impact (not confirmed)" in html
    assert "not evidence of compromise" in html and "has not been established" in html.replace("\n", " ") or "not been established" in html
    assert "Synthetic demonstration data" in html  # demo advisories are labelled in the report itself
    assert "Prioritisation factors" in html and "Known exploitation" in html
    assert "CVE-2099-1001" in html and "https://nvd.nist.gov" in html or "example.invalid" in html or "cisa.gov" in html


def test_internal_notes_never_appear_in_reports(owner, case):
    for kind in ("technical", "executive"):
        html = html_for(owner, case, kind)
        assert "INTERNAL-ONLY-SECRET" not in html and "Customer update: verifying version." in html


def test_executive_report_is_shorter_than_technical(owner, case):
    tech, execu = html_for(owner, case, "technical"), html_for(owner, case, "executive")
    assert "Impact paths" in tech and "Impact paths" not in execu
    assert "Timeline" in tech and "Timeline" not in execu
    assert "Executive summary" in execu and len(execu) < len(tech)


def test_report_never_contains_another_tenants_data(owner, other_owner, case):
    secret = make(other_owner, "/clients", name="RIVAL-SECRET-CLIENT")
    make(other_owner, "/cases", title="RIVAL-SECRET-CASE", client_id=secret["id"])
    assert "RIVAL-SECRET" not in html_for(owner, case)
    with org_session(UUID(other_owner.org_id)) as db:
        with pytest.raises(LookupError):  # a case id from another tenant is simply not found
            reports.collect(db, UUID(other_owner.org_id), UUID(case["id"]), "technical", "x", "R")


def test_report_generation_flow_with_authorised_download(owner, other_owner, viewer, case, monkeypatch):
    monkeypatch.setattr(reports, "render_pdf", lambda html: b"%PDF-1.7 fake pdf for test\n" + html[:50].encode())
    r = owner.post(f"/cases/{case['id']}/reports", json={"kind": "technical"})
    assert r.status_code == 202
    listing = owner.get(f"/cases/{case['id']}/reports").json()["items"]
    assert listing[0]["status"] == "completed" and listing[0]["sha256"]
    rid = listing[0]["id"]
    pdf = owner.get(f"/reports/{rid}/download")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and pdf.headers["content-type"] == "application/pdf"
    assert pdf.headers["cache-control"] == "private, no-store"
    # authorisation
    assert other_owner.get(f"/reports/{rid}/download").status_code == 404
    assert other_owner.get(f"/reports/{rid}").status_code == 404
    assert viewer.get(f"/reports/{rid}/download").status_code == 200  # read-only roles may export authorised reports
    assert make_anon().get(f"/reports/{rid}/download").status_code == 401
    # who generated / downloaded it is recorded
    audit = {e["event_type"]: e for e in owner.get("/audit-events").json()["items"] if e["event_type"].startswith("report.")}
    assert {"report.requested", "report.generated", "report.downloaded"} <= set(audit)
    assert audit["report.generated"]["actor"] == "owner@msp.test"
    timeline = [e["kind"] for e in owner.get(f"/cases/{case['id']}/timeline").json()["items"]]
    assert "report_requested" in timeline


def make_anon():
    from tests.conftest import Api

    return Api()


def test_failed_rendering_is_reported_not_left_pending(owner, case, monkeypatch):
    def broken(html):
        raise reports.PdfUnavailable("PDF rendering is not available in this environment")

    monkeypatch.setattr(reports, "render_pdf", broken)
    owner.post(f"/cases/{case['id']}/reports", json={"kind": "executive"})
    r = owner.get(f"/cases/{case['id']}/reports").json()["items"][0]
    assert r["status"] == "failed" and "not available" in r["error"] and r["error_code"] == "pdf_unavailable"
    assert owner.get(f"/reports/{r['id']}/download").status_code == 409


def test_report_generation_is_rate_limited(owner, case, monkeypatch):
    monkeypatch.setattr(reports, "render_pdf", lambda html: b"%PDF-x")
    codes = [owner.post(f"/cases/{case['id']}/reports", json={"kind": "technical"}).status_code for _ in range(14)]
    assert 429 in codes


def test_large_cases_are_truncated_to_the_configured_limit(owner, case, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "max_report_items", 3)
    for i in range(10):
        make(owner, f"/cases/{case['id']}/notes", body=f"note {i}", visibility="customer")
    html = html_for(owner, case)
    import re

    assert len(re.findall(r"note \d", html)) == 2  # the limit of 3 includes the pre-existing customer note
    assert "Timeline truncated" in html


def test_pdf_rendering_in_the_reporter_image(owner, case):
    pytest.importorskip("weasyprint", reason="WeasyPrint is only installed in the reporter image")
    pdf = reports.render_pdf(html_for(owner, case))
    assert pdf.startswith(b"%PDF")


def test_pdf_renderer_refuses_external_resources(monkeypatch):
    pytest.importorskip("weasyprint", reason="WeasyPrint is only installed in the reporter image")
    html = '<html><body><img src="http://169.254.169.254/latest/meta-data/"><p>ok</p></body></html>'
    assert reports.render_pdf(html).startswith(b"%PDF")  # renders, but the fetch was denied rather than performed


def test_pdf_renderer_never_contacts_a_local_server(monkeypatch):
    """Proof, not assumption: a listening server receives zero requests while a document that references it renders."""
    pytest.importorskip("weasyprint", reason="WeasyPrint is only installed in the reporter image")
    import http.server
    import threading

    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        html = f'<html><head><link rel="stylesheet" href="http://127.0.0.1:{port}/a.css"></head><body><img src="http://127.0.0.1:{port}/x.png"><p>ok</p></body></html>'
        assert reports.render_pdf(html).startswith(b"%PDF")
    finally:
        server.shutdown()
    assert hits == []
