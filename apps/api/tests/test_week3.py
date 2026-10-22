"""Week 3: case workflow, evidence provenance and retention, remediation verification, report job lifecycle."""

import io
from datetime import date, timedelta
from uuid import UUID

import pytest

from app.db import org_session
from app.models import AuditEvent, Report, utcnow
from app.services import reports
from app.services.storage import storage
from sqlalchemy import select

from .helpers import load_fixtures, make, scenario


@pytest.fixture
def case(owner):
    scenario(owner)
    load_fixtures()
    owner.post("/correlation-runs")
    a = next(x for x in owner.get("/assessments?limit=100").json()["items"] if x["advisory"] == "CVE-2099-1001" and x["client"] == "Retail Client")
    c = make(owner, "/cases", title="Acme Insight Agent exposure", assessment_ids=[a["id"]], assignee_id=owner.user_id)
    return {"case": c, "assessment": a}


def transition(api, cid, to, version, **kw):
    return api.post(f"/cases/{cid}/transition", json={"to": to, "version": version, **kw})


def upload(api, cid, name, data, **form):
    return api.post(f"/cases/{cid}/evidence/files", files={"file": (name, io.BytesIO(data), "text/plain")}, data=form)


def audit_actions(owner):
    with org_session(UUID(owner.org_id)) as db:
        return [e.event_type for e in db.scalars(select(AuditEvent).order_by(AuditEvent.occurred_at))]


# ------------------------------------------------------------------------------------ Day 15: cases
def test_lifecycle_includes_evidence_collection_and_remediation(owner, case):
    cid, v = case["case"]["id"], case["case"]["version"]
    path = ["triage", "investigating", "evidence_collection", "remediation", "resolved"]
    for to in path:
        r = transition(owner, cid, to, v, resolution_summary="Patched and checked.")
        assert r.status_code == 200, (to, r.text)
        v = r.json()["version"]
    assert owner.get(f"/cases/{cid}").json()["status"] == "resolved"
    # new evidence reopens a resolved case
    assert transition(owner, cid, "investigating", v, note="New log found.").status_code == 200


def test_phases_cannot_be_skipped(owner, case):
    cid, v = case["case"]["id"], case["case"]["version"]
    assert transition(owner, cid, "remediation", v).status_code == 409  # new -> remediation
    assert transition(owner, cid, "evidence_collection", v).status_code == 409
    assert owner.post(f"/cases/{cid}/transition", json={"to": "bogus", "version": v}).status_code == 422


def test_case_severity_comes_from_the_advisory_and_can_be_corrected(owner, case):
    c = case["case"]
    assert c["severity"] in ("critical", "high", "medium", "low")
    r = owner.patch(f"/cases/{c['id']}", json={"version": c["version"], "severity": "low"})
    assert r.status_code == 200 and r.json()["severity"] == "low"
    assert owner.patch(f"/cases/{c['id']}", json={"version": r.json()["version"], "severity": "urgent"}).status_code == 422
    assert owner.get("/cases?severity=low").json()["total"] == 1 and owner.get("/cases?severity=critical").json()["total"] == 0
    kinds = [e["kind"] for e in owner.get(f"/cases/{c['id']}/timeline").json()["items"]]
    assert "severity_changed" in kinds  # a change of severity is a recorded, attributed event


def test_list_supports_sort_reference_search_and_overdue_counts(owner, case):
    cid = case["case"]["id"]
    make(owner, "/cases", title="Second investigation", priority="low")
    make(owner, f"/cases/{cid}/tasks", title="Rotate the shared secret", due_date=str(date.today() - timedelta(days=3)))
    make(owner, f"/cases/{cid}/tasks", title="Review access logs", due_date=str(date.today() + timedelta(days=3)))
    first = next(i for i in owner.get("/cases").json()["items"] if i["id"] == cid)
    assert first["open_tasks"] == 2 and first["overdue_tasks"] == 1
    assert [i["reference"] for i in owner.get("/cases?q=VEY-0002").json()["items"]] == ["VEY-0002"]
    assert [i["reference"] for i in owner.get("/cases?q=2").json()["items"]] == ["VEY-0002"]
    asc = [i["number"] for i in owner.get("/cases?sort=number&direction=asc").json()["items"]]
    assert asc == sorted(asc)
    assert owner.get("/cases?sort=password_hash").status_code == 422  # only allow-listed sort columns


def test_assessments_can_be_linked_later_but_never_across_tenants(owner, other_owner, case):
    cid = case["case"]["id"]
    other = [x for x in owner.get("/assessments?limit=100").json()["items"] if x["id"] != case["assessment"]["id"]][0]
    r = owner.post(f"/cases/{cid}/assessments", json={"assessment_ids": [other["id"], case["assessment"]["id"]]})
    assert r.status_code == 200 and r.json()["linked"] == [other["id"]]  # the already linked one is skipped
    assert owner.post(f"/cases/{cid}/assessments", json={"assessment_ids": [other["id"]]}).json()["linked"] == []
    # another organization can neither link into this case nor link this organization's assessment into its own case
    assert other_owner.post(f"/cases/{cid}/assessments", json={"assessment_ids": [other["id"]]}).status_code == 404
    rival_case = make(other_owner, "/cases", title="Rival investigation")
    assert other_owner.post(f"/cases/{rival_case['id']}/assessments", json={"assessment_ids": [other["id"]]}).status_code == 404


# ------------------------------------------------------------------------------------ Day 17: evidence
def test_evidence_records_when_collected_and_who_added_it(owner, case):
    cid = case["case"]["id"]
    ev = upload(owner, cid, "agent-version.txt", b"Insight Agent 4.1.0\n", title="Version check", collected_at="2026-01-02T03:04:05Z").json()
    assert ev["collected_at"].startswith("2026-01-02T03:04:05") and ev["added_by"] == owner.user_id and len(ev["sha256"]) == 64
    assert ev["retrieved_at"] > ev["collected_at"]  # Veylith's own recording time is kept separately


def test_evidence_can_only_reference_an_assessment_linked_to_the_case(owner, case):
    cid = case["case"]["id"]
    unlinked = [x for x in owner.get("/assessments?limit=100").json()["items"] if x["id"] != case["assessment"]["id"]][0]
    assert owner.post(f"/cases/{cid}/evidence", json={"kind": "note", "title": "t", "assessment_id": unlinked["id"]}).status_code == 422
    assert owner.post(f"/cases/{cid}/evidence", json={"kind": "note", "title": "t", "assessment_id": case["assessment"]["id"]}).status_code == 201


def test_a_modified_stored_file_is_detected_and_not_served(owner, case):
    cid = case["case"]["id"]
    ev = upload(owner, cid, "log.txt", b"original log line\n").json()
    assert owner.get(f"/evidence/{ev['id']}/integrity").json()["ok"] is True
    storage().path(UUID(owner.org_id), _key(owner, ev["id"])).write_bytes(b"tampered\n")
    check = owner.get(f"/evidence/{ev['id']}/integrity").json()
    assert check["ok"] is False and check["actual_sha256"] != check["recorded_sha256"]
    assert owner.get(f"/evidence/{ev['id']}/download").status_code == 409
    assert "evidence.integrity_failed" in audit_actions(owner)


def _key(owner, evidence_id):
    from app.models import Evidence

    with org_session(UUID(owner.org_id)) as db:
        return db.get(Evidence, UUID(evidence_id)).storage_key


def test_evidence_deletion_is_restricted_reasoned_and_retains_the_object(owner, analyst, viewer, case):
    cid = case["case"]["id"]
    ev = upload(owner, cid, "notes.txt", b"keep me\n").json()
    key = _key(owner, ev["id"])
    assert analyst.request("DELETE", f"/evidence/{ev['id']}", json={"reason": "mistake"}).status_code == 403
    assert viewer.request("DELETE", f"/evidence/{ev['id']}", json={"reason": "mistake"}).status_code == 403
    assert owner.request("DELETE", f"/evidence/{ev['id']}", json={}).status_code == 422  # a reason is mandatory
    assert owner.request("DELETE", f"/evidence/{ev['id']}", json={"reason": "Uploaded to the wrong case"}).status_code == 200
    assert owner.get(f"/evidence/{ev['id']}").status_code == 404 and owner.get(f"/evidence/{ev['id']}/download").status_code == 404
    assert ev["id"] not in [e["id"] for e in owner.get(f"/cases/{cid}/evidence").json()["items"]]
    assert storage().path(UUID(owner.org_id), key).is_file()  # soft delete: the object and its hash survive for retention
    assert "evidence.deleted" in audit_actions(owner)
    assert "evidence_deleted" in [e["kind"] for e in owner.get(f"/cases/{cid}/timeline").json()["items"]]
    assert owner.request("DELETE", f"/evidence/{ev['id']}", json={"reason": "again"}).status_code == 404


def test_other_tenants_cannot_read_or_delete_evidence(owner, other_owner, case):
    ev = upload(owner, case["case"]["id"], "x.txt", b"private\n").json()
    for path in (f"/evidence/{ev['id']}", f"/evidence/{ev['id']}/download", f"/evidence/{ev['id']}/integrity"):
        assert other_owner.get(path).status_code == 404
    assert other_owner.request("DELETE", f"/evidence/{ev['id']}", json={"reason": "cleanup"}).status_code == 404
    assert other_owner.post(f"/evidence/{ev['id']}/verify", json={"verification_status": "verified"}).status_code == 404


# ------------------------------------------------------------------------------------ Day 18: remediation
def done_task(owner, cid, **kw):
    t = make(owner, f"/cases/{cid}/tasks", title="Upgrade Insight Agent to 4.2.1")
    r = owner.patch(f"/tasks/{t['id']}", json={"status": "done", "completion_notes": "Upgraded on the production host.", **kw})
    assert r.status_code == 200, r.text
    return r.json()


def test_completed_is_not_verified(owner, case):
    t = done_task(owner, case["case"]["id"])
    assert t["status"] == "done" and t["completed_at"] and t["verification_status"] == "unverified" and t["verified_by"] is None


def test_verification_records_who_when_and_how(owner, analyst, case):
    cid = case["case"]["id"]
    t = done_task(owner, cid)
    ev = make(owner, f"/cases/{cid}/evidence", kind="note", title="Re-scan output", excerpt="Insight Agent 4.2.1 confirmed")
    r = analyst.post(f"/tasks/{t['id']}/verify", json={"verification_status": "verified", "notes": "Re-ran the version check.", "evidence_id": ev["id"]})
    assert r.status_code == 200
    v = r.json()
    assert v["verification_status"] == "verified" and v["verified_by"] == analyst.user_id and v["verified_at"] and v["verification_evidence_id"] == ev["id"]
    assert "task.verified" in audit_actions(owner)
    assert "task_verified" in [e["kind"] for e in owner.get(f"/cases/{cid}/timeline").json()["items"]]
    # the spec's alias paths behave identically
    assert owner.get(f"/remediation-tasks/{t['id']}").json()["verification_status"] == "verified"
    assert len(owner.get(f"/cases/{cid}/remediation-tasks").json()["items"]) == 1


def test_verification_rules(owner, viewer, case):
    cid = case["case"]["id"]
    open_task = make(owner, f"/cases/{cid}/tasks", title="Apply the vendor patch")
    assert owner.post(f"/tasks/{open_task['id']}/verify", json={"verification_status": "verified", "notes": "x"}).status_code == 409  # not completed yet
    t = done_task(owner, cid)
    assert viewer.post(f"/tasks/{t['id']}/verify", json={"verification_status": "verified", "notes": "x"}).status_code == 403  # read-only role
    assert owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "verified"}).status_code == 422  # needs notes or evidence
    assert owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "rejected"}).status_code == 422  # rejection must say why
    assert owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "approved", "notes": "x"}).status_code == 422
    other_case = make(owner, "/cases", title="Unrelated investigation")
    foreign = make(owner, f"/cases/{other_case['id']}/evidence", kind="note", title="Other")
    assert owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "verified", "evidence_id": foreign["id"]}).status_code == 422


def test_rejected_verification_sends_the_task_back_to_work(owner, case):
    t = done_task(owner, case["case"]["id"])
    r = owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "rejected", "notes": "Host still reports 4.1.0."}).json()
    assert r["verification_status"] == "rejected" and r["status"] == "in_progress" and r["completed_at"] is None


def test_changing_a_verified_claim_clears_the_verification(owner, case):
    cid = case["case"]["id"]
    t = done_task(owner, cid)
    owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "verified", "notes": "Checked."})
    r = owner.patch(f"/tasks/{t['id']}", json={"completion_notes": "Actually only the staging host was upgraded."}).json()
    assert r["verification_status"] == "unverified" and r["verified_by"] is None and r["verified_at"] is None
    assert "task_verification_reset" in [e["kind"] for e in owner.get(f"/cases/{cid}/timeline").json()["items"]]


def test_evidence_that_supports_a_verified_task_cannot_be_deleted(owner, case):
    cid = case["case"]["id"]
    ev = make(owner, f"/cases/{cid}/evidence", kind="note", title="Re-scan output", excerpt="4.2.1")
    t = done_task(owner, cid)
    owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "verified", "evidence_id": ev["id"]})
    assert owner.request("DELETE", f"/evidence/{ev['id']}", json={"reason": "cleanup"}).status_code == 409


def test_other_tenants_cannot_touch_tasks(owner, other_owner, case):
    t = done_task(owner, case["case"]["id"])
    assert other_owner.get(f"/tasks/{t['id']}").status_code == 404
    assert other_owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "verified", "notes": "x"}).status_code == 404
    assert other_owner.patch(f"/tasks/{t['id']}", json={"status": "open"}).status_code == 404


# ------------------------------------------------------------------------------------ Days 19-20: report jobs
def fake_pdf(monkeypatch, calls=None):
    def render(html):
        if calls is not None:
            calls.append(1)
        return b"%PDF-1.7 synthetic"

    monkeypatch.setattr(reports, "render_pdf", render)


def insert_report(owner, case, status, **kw):
    with org_session(UUID(owner.org_id)) as db:
        r = Report(organization_id=UUID(owner.org_id), case_id=UUID(case["case"]["id"]), kind="technical", status=status, requested_by=UUID(owner.user_id), **kw)
        db.add(r)
        db.commit()
        return str(r.id)


def test_report_job_exposes_template_version_and_attempts(owner, case, monkeypatch):
    fake_pdf(monkeypatch)
    r = owner.get(f"/reports/{make(owner, f'/cases/{case['case']['id']}/reports', kind='technical')['id']}").json()
    assert r["status"] == "completed" and r["template_version"] == reports.TEMPLATE_VERSION and r["attempts"] == 1 and r["error_code"] is None


def test_a_job_already_in_flight_is_returned_instead_of_duplicated(owner, case):
    live = insert_report(owner, case, "queued")
    again = owner.post(f"/cases/{case['case']['id']}/reports", json={"kind": "technical"})
    assert again.status_code == 202 and again.json()["id"] == live
    assert len(owner.get(f"/cases/{case['case']['id']}/reports").json()["items"]) == 1
    # a different kind is different work
    assert owner.post(f"/cases/{case['case']['id']}/reports", json={"kind": "executive"}).json()["id"] != live


def test_failed_job_shows_a_safe_message_and_never_internal_detail(owner, case, monkeypatch):
    def boom(html):
        raise RuntimeError("psycopg connection to 10.0.0.5 failed; file /srv/veylith/secret/key.pem")

    monkeypatch.setattr(reports, "render_pdf", boom)
    r = make(owner, f"/cases/{case['case']['id']}/reports", kind="technical")
    body = owner.get(f"/reports/{r['id']}").json()
    assert body["status"] == "failed" and body["error_code"] == "render_failed" and body["retryable"] is True
    assert "10.0.0.5" not in str(body) and "/srv" not in str(body) and "key.pem" not in str(body)
    with org_session(UUID(owner.org_id)) as db:
        assert "10.0.0.5" in db.get(Report, UUID(r["id"])).error  # kept internally for operators
    assert "report.failed" in audit_actions(owner)
    assert "report_failed" in [e["kind"] for e in owner.get(f"/cases/{case['case']['id']}/timeline").json()["items"]]
    assert "10.0.0.5" not in str(owner.get("/reports").json())


def test_failure_categories_are_classified(monkeypatch):
    assert reports.classify(reports.PdfUnavailable("x")) == "pdf_unavailable"
    assert reports.classify(LookupError()) == "case_unavailable"
    assert reports.classify(PermissionError()) == "storage_failed"
    assert reports.classify(TimeoutError()) == "timeout"
    assert reports.classify(ValueError()) == "render_failed"


def test_retrying_a_failed_job_succeeds_and_is_safe_to_repeat(owner, case, monkeypatch):
    monkeypatch.setattr(reports, "render_pdf", lambda html: (_ for _ in ()).throw(reports.PdfUnavailable("down")))
    job = make(owner, f"/cases/{case['case']['id']}/reports", kind="technical")
    assert owner.get(f"/reports/{job['id']}").json()["status"] == "failed"
    calls = []
    fake_pdf(monkeypatch, calls)
    retried = owner.post(f"/reports/{job['id']}/retry")
    assert retried.status_code == 202
    done = owner.get(f"/reports/{job['id']}").json()
    assert done["status"] == "completed" and done["attempts"] == 2 and done["error_code"] is None
    owner.post(f"/reports/{job['id']}/retry")  # a second retry of a finished job does nothing
    assert len(calls) == 1 and owner.get(f"/reports/{job['id']}").json()["attempts"] == 2
    assert owner.get(f"/reports/{job['id']}/download").content.startswith(b"%PDF")


def test_redelivered_task_produces_one_report_only(owner, case, monkeypatch):
    calls = []
    fake_pdf(monkeypatch, calls)
    rid = make(owner, f"/cases/{case['case']['id']}/reports", kind="technical")["id"]
    with org_session(UUID(owner.org_id)) as db:
        first_key = db.get(Report, UUID(rid)).storage_key
    for _ in range(2):  # the broker redelivers the message after a worker crash
        with org_session(UUID(owner.org_id)) as db:
            assert reports.generate(db, UUID(owner.org_id), UUID(rid)).status == "completed"
    with org_session(UUID(owner.org_id)) as db:
        r = db.get(Report, UUID(rid))
        assert r.storage_key == first_key and r.attempts == 1
    assert len(calls) == 1


def test_a_job_another_worker_is_processing_is_left_alone_until_it_goes_stale(owner, case, monkeypatch):
    calls = []
    fake_pdf(monkeypatch, calls)
    rid = insert_report(owner, case, "processing", started_at=utcnow(), attempts=1)
    with org_session(UUID(owner.org_id)) as db:
        assert reports.generate(db, UUID(owner.org_id), UUID(rid)).status == "processing"
    assert calls == [] and owner.get(f"/reports/{rid}").json()["retryable"] is False
    stale = insert_report(owner, case, "processing", started_at=utcnow() - timedelta(hours=1), attempts=1)
    assert owner.get(f"/reports/{stale}").json()["retryable"] is True  # the worker that took it is gone
    assert owner.post(f"/reports/{stale}/retry").status_code == 202
    assert owner.get(f"/reports/{stale}").json()["status"] == "completed"


def test_report_actions_respect_roles_and_tenants(owner, other_owner, viewer, case, monkeypatch):
    fake_pdf(monkeypatch)
    rid = make(owner, f"/cases/{case['case']['id']}/reports", kind="technical")["id"]
    assert viewer.post(f"/reports/{rid}/retry").status_code == 403
    assert other_owner.post(f"/reports/{rid}/retry").status_code == 404
    assert other_owner.get(f"/reports/{rid}").status_code == 404 and other_owner.get(f"/reports/{rid}/download").status_code == 404
    assert other_owner.get("/reports").json()["total"] == 0


def test_report_shows_verification_separately_from_completion(owner, case, monkeypatch):
    from .test_reports import html_for

    cid = case["case"]["id"]
    done_task(owner, cid)
    html = html_for(owner, case["case"])
    assert "have <strong>not</strong> been independently verified" in html and "Outstanding risks" in html and "CONFIDENTIAL" in html
    assert "Scope and methodology" in html and "template v" in html


def test_deleted_evidence_is_not_in_reports(owner, case):
    from .test_reports import html_for

    cid = case["case"]["id"]
    ev = make(owner, f"/cases/{cid}/evidence", kind="note", title="Mistaken note", excerpt="REMOVED-EXCERPT-MARKER")
    assert "REMOVED-EXCERPT-MARKER" in html_for(owner, case["case"])
    owner.request("DELETE", f"/evidence/{ev['id']}", json={"reason": "Entered by mistake"})
    assert "REMOVED-EXCERPT-MARKER" not in html_for(owner, case["case"])


# ------------------------------------------------------------------------------------ Day 21: the whole incident
def test_complete_incident_lifecycle_with_two_organizations(owner, other_owner, viewer, case, monkeypatch):
    fake_pdf(monkeypatch)
    cid, v = case["case"]["id"], case["case"]["version"]
    # the match keeps its rationale; the case is linked to it; it stays *potential* until an analyst establishes more
    assert case["assessment"]["state"] in ("potential_impact", "insufficient_data")
    ev = upload(owner, cid, "agent-version.txt", b"Insight Agent 4.1.0\n", title="Installed version", assessment_id=case["assessment"]["id"], collected_at="2026-01-02T10:00:00Z").json()
    assert len(ev["sha256"]) == 64
    for to in ("triage", "investigating", "evidence_collection", "remediation"):
        v = transition(owner, cid, to, v).json()["version"]
    t = make(owner, f"/cases/{cid}/tasks", title="Upgrade to 4.2.1", assignee_id=owner.user_id, due_date=str(date.today() + timedelta(days=2)))
    proof = make(owner, f"/cases/{cid}/evidence", kind="note", title="Post-upgrade version", excerpt="4.2.1")
    owner.patch(f"/tasks/{t['id']}", json={"status": "done", "completion_notes": "Upgraded."})
    assert owner.get(f"/tasks/{t['id']}").json()["verification_status"] == "unverified"
    owner.post(f"/tasks/{t['id']}/verify", json={"verification_status": "verified", "notes": "Version re-checked.", "evidence_id": proof["id"]})
    assert transition(owner, cid, "resolved", v, resolution_summary="Upgraded and verified.").status_code == 200
    rid = make(owner, f"/cases/{cid}/reports", kind="technical")["id"]
    assert owner.get(f"/reports/{rid}/download").status_code == 200 and viewer.get(f"/reports/{rid}/download").status_code == 200
    # a user from another organization reaches none of it
    for path in (f"/cases/{cid}", f"/cases/{cid}/timeline", f"/cases/{cid}/evidence", f"/cases/{cid}/tasks", f"/cases/{cid}/reports",
                 f"/evidence/{ev['id']}", f"/evidence/{ev['id']}/download", f"/tasks/{t['id']}", f"/reports/{rid}", f"/reports/{rid}/download"):
        assert other_owner.get(path).status_code == 404, path
    actions = audit_actions(owner)
    for expected in ("case.created", "evidence.uploaded", "case.status_changed", "task.created", "task.updated", "task.verified", "report.requested", "report.generated", "report.downloaded"):
        assert expected in actions, expected
