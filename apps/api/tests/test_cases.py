import io
from datetime import date, timedelta

import pytest

from .helpers import load_fixtures, make, scenario


@pytest.fixture
def case(owner):
    scenario(owner)
    load_fixtures()
    owner.post("/correlation-runs")
    a = next(x for x in owner.get("/assessments?limit=100").json()["items"] if x["advisory"] == "CVE-2099-1001" and x["client"] == "Retail Client")
    c = make(owner, "/cases", title="Acme Insight Agent exposure", assessment_ids=[a["id"]], assignee_id=owner.user_id)
    return {"case": c, "assessment": a}


def transition(api, case_id, to, version, **kw):
    return api.post(f"/cases/{case_id}/transition", json={"to": to, "version": version, **kw})


def test_case_created_from_assessment_inherits_context(owner, case):
    c = case["case"]
    assert c["reference"] == "VEY-0001" and c["status"] == "new"
    assert c["client"] == "Retail Client" and c["advisory"] == "CVE-2099-1001"
    assert c["priority"] == case["assessment"]["priority"]
    second = make(owner, "/cases", title="Another")
    assert second["reference"] == "VEY-0002"


def test_full_lifecycle_with_audit_and_timeline(owner, case):
    cid = case["case"]["id"]
    v = case["case"]["version"]
    for to in ("triage", "investigating"):
        r = transition(owner, cid, to, v)
        assert r.status_code == 200, r.text
        v = r.json()["version"]
    task = make(owner, f"/cases/{cid}/tasks", title="Verify deployed version")
    blocked = transition(owner, cid, "resolved", v, resolution_summary="Patched.")
    assert blocked.status_code == 409 and "task" in blocked.json()["detail"]  # open remediation work blocks resolution
    assert owner.patch(f"/tasks/{task['id']}", json={"status": "done"}).status_code == 422  # completion notes required
    done = owner.patch(f"/tasks/{task['id']}", json={"status": "done", "completion_notes": "Version is 4.1.0; upgraded to 4.2.1."})
    assert done.json()["status"] == "done" and done.json()["completed_at"]
    r = transition(owner, cid, "resolved", v, resolution_summary="Upgraded to 4.2.1.")
    assert r.status_code == 200
    v = r.json()["version"]
    assert transition(owner, cid, "closed", v, resolution_summary="Upgraded to 4.2.1.").status_code == 422  # closure reason required
    closed = transition(owner, cid, "closed", v, resolution_summary="Upgraded to 4.2.1.", closure_reason="resolved")
    assert closed.status_code == 200 and closed.json()["status"] == "closed"

    tl = owner.get(f"/cases/{cid}/timeline").json()["items"]
    kinds = [e["kind"] for e in tl]
    assert kinds[0] == "case_created" and kinds.count("status_changed") == 4
    system = [e for e in tl if e["is_system"]]
    assert {e["kind"] for e in system} == {"advisory_context", "assessment_linked"} and all(e["actor"] == "system" for e in system)
    ctx_event = next(e for e in system if e["kind"] == "advisory_context")
    assert ctx_event["data"]["external_published_at"] and ctx_event["data"]["first_observed_at"]  # external vs observed time kept apart
    assert all("occurred_at" in e for e in tl)
    audit = [e for e in owner.get(f"/audit-events?object_type=case&object_id={cid}").json()["items"]]
    changes = [e["metadata"] for e in audit if e["event_type"] == "case.status_changed"]
    assert {"previous_status": "resolved", "new_status": "closed", "closure_reason": "resolved"} in changes


def test_invalid_transitions_are_rejected(owner, case):
    cid, v = case["case"]["id"], case["case"]["version"]
    assert transition(owner, cid, "resolved", v, resolution_summary="x").status_code == 409  # cannot skip triage/investigation
    assert transition(owner, cid, "new", v).status_code == 409
    r = transition(owner, cid, "closed", v, closure_reason="false_positive", resolution_summary="Not our product.")
    assert r.status_code == 200
    v = r.json()["version"]
    assert transition(owner, cid, "investigating", v).status_code == 409  # a closed case cannot silently change state
    assert transition(owner, cid, "triage", v).status_code == 422  # reopening needs a recorded reason
    reopened = transition(owner, cid, "triage", v, note="New intelligence from vendor.")
    assert reopened.status_code == 200 and reopened.json()["closure_reason"] == ""
    events = [e["summary"] for e in owner.get(f"/cases/{cid}/timeline").json()["items"] if e["kind"] == "status_changed"]
    assert any("New intelligence" in s for s in events)


def test_concurrent_updates_are_detected(owner, analyst, case):
    cid, v = case["case"]["id"], case["case"]["version"]
    assert owner.patch(f"/cases/{cid}", json={"version": v, "title": "Edited by the owner"}).status_code == 200
    stale = analyst.patch(f"/cases/{cid}", json={"version": v, "title": "Stale write"})
    assert stale.status_code == 409
    assert transition(analyst, cid, "triage", v).status_code == 409
    assert owner.get(f"/cases/{cid}").json()["title"] == "Edited by the owner"  # the stale write did not overwrite it


def test_assignment_and_filters(owner, analyst, case):
    cid, v = case["case"]["id"], case["case"]["version"]
    r = owner.patch(f"/cases/{cid}", json={"version": v, "assignee_id": analyst.user_id, "due_date": str(date.today() - timedelta(days=2))})
    assert r.json()["assignee_id"] == analyst.user_id
    assert owner.get(f"/cases?assignee_id={analyst.user_id}").json()["total"] == 1
    assert owner.get("/cases?overdue=true").json()["total"] == 1
    assert owner.get("/cases?status=triage").json()["total"] == 0
    assert owner.get("/cases?priority=low").json()["total"] in (0, 1)
    assert owner.get(f"/cases?client_id={case['assessment']['client_id']}").json()["total"] == 1
    unassigned = owner.patch(f"/cases/{cid}", json={"version": r.json()["version"], "unassign": True}).json()
    assert unassigned["assignee_id"] is None


def test_internal_notes_stay_internal(owner, viewer, case):
    cid = case["case"]["id"]
    make(owner, f"/cases/{cid}/notes", body="Suspect the vendor is hiding scope.", visibility="internal")
    make(owner, f"/cases/{cid}/notes", body="We are verifying the affected version.", visibility="customer")
    assert len(owner.get(f"/cases/{cid}/notes").json()["items"]) == 2
    seen = viewer.get(f"/cases/{cid}/notes").json()["items"]
    assert [n["body"] for n in seen] == ["We are verifying the affected version."]
    assert viewer.post(f"/cases/{cid}/notes", json={"body": "x"}).status_code == 403


def test_task_lifecycle_and_overdue(owner, case):
    cid = case["case"]["id"]
    t = make(owner, f"/cases/{cid}/tasks", title="Rotate integration credentials", priority="high", due_date=str(date.today() - timedelta(days=1)), assignee_id=owner.user_id)
    assert t["overdue"] is True
    assert owner.get("/tasks?overdue=true").json()["total"] == 1
    assert owner.patch(f"/tasks/{t['id']}", json={"status": "in_progress"}).json()["status"] == "in_progress"
    assert owner.patch(f"/tasks/{t['id']}", json={"status": "blocked"}).json()["status"] == "blocked"
    assert owner.patch(f"/tasks/{t['id']}", json={"status": "done", "completion_notes": "Done"}).json()["overdue"] is False
    assert owner.post(f"/cases/{cid}/tasks", json={"title": "x"}).status_code == 422  # too short
    assert owner.post(f"/cases/{cid}/tasks", json={"title": "Valid title", "assignee_id": "00000000-0000-0000-0000-000000000000"}).status_code == 422


# ---- evidence -----------------------------------------------------------------------------------
def upload(api, cid, name, data, ctype="text/plain", **form):
    return api.post(f"/cases/{cid}/evidence/files", files={"file": (name, io.BytesIO(data), ctype)}, data=form)


def test_evidence_upload_stores_hash_and_serves_safely(owner, case):
    import hashlib

    cid = case["case"]["id"]
    body = b"timestamp,src\n2099-01-01,10.0.0.1\n"
    r = upload(owner, cid, "../../etc/auth log.csv", body, "text/csv", title="Auth log export", source_name="Customer SIEM")
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["sha256"] == hashlib.sha256(body).hexdigest() and ev["size_bytes"] == len(body)
    assert ev["original_filename"] == "auth log.csv" and ev["content_type"] == "text/csv"
    assert "storage_key" not in ev and ev["verification_status"] == "unverified"
    dl = owner.get(f"/evidence/{ev['id']}/download")
    assert dl.content == body
    assert dl.headers["content-disposition"].startswith("attachment") and dl.headers["x-content-type-options"] == "nosniff"
    types = [e["event_type"] for e in owner.get("/audit-events").json()["items"]]
    assert "evidence.uploaded" in types and "evidence.downloaded" in types


def test_evidence_upload_rules(owner, viewer, case):
    cid = case["case"]["id"]
    assert upload(owner, cid, "shell.php", b"<?php system($_GET[1]);").status_code == 415
    assert upload(owner, cid, "page.html", b"<script>alert(1)</script>").status_code == 415
    assert upload(owner, cid, "fake.png", b"this is not a png").status_code == 415  # content must match the extension
    assert upload(owner, cid, "empty.txt", b"").status_code == 422
    assert upload(owner, cid, "bin.txt", b"abc\x00def").status_code == 415
    assert upload(owner, cid, "big.txt", b"a" * (10 * 1024 * 1024 + 1)).status_code == 413
    assert upload(owner, cid, "ok.png", b"\x89PNG\r\n\x1a\n" + b"0" * 20, "image/png").status_code == 201
    assert upload(viewer, cid, "ok.txt", b"hello").status_code == 403


def test_evidence_files_are_private_and_not_guessable(owner, other_owner, case, tmp_path):
    cid = case["case"]["id"]
    ev = upload(owner, cid, "a.txt", b"secret").json()
    assert other_owner.get(f"/evidence/{ev['id']}/download").status_code == 404
    assert other_owner.get(f"/evidence/{ev['id']}").status_code == 404
    import os
    from pathlib import Path

    files = [p for p in Path(os.environ["STORAGE_DIR"]).rglob("*") if p.is_file()]
    assert files and all(p.name.isalnum() and "a.txt" not in str(p) for p in files)  # generated names only


def test_url_evidence_is_validated_and_never_fetched(owner, case):
    cid = case["case"]["id"]
    ok = make(owner, f"/cases/{cid}/evidence", kind="url", title="Vendor advisory", source_name="Acme PSIRT", source_url="https://acme.example/psirt/1", excerpt="Affected: <4.2.1")
    assert ok["source_url"].startswith("https://")
    for bad in ("javascript:alert(1)", "file:///etc/passwd", "ftp://x"):
        assert owner.post(f"/cases/{cid}/evidence", json={"kind": "url", "title": "t", "source_url": bad}).status_code == 422
    assert owner.post(f"/cases/{cid}/evidence", json={"kind": "url", "title": "t"}).status_code == 422


def test_task_can_cite_verification_evidence(owner, case):
    cid = case["case"]["id"]
    ev = make(owner, f"/cases/{cid}/evidence", kind="note", title="Version screenshot", excerpt="4.2.1")
    t = make(owner, f"/cases/{cid}/tasks", title="Confirm patched version")
    r = owner.patch(f"/tasks/{t['id']}", json={"status": "done", "completion_notes": "Confirmed.", "verification_evidence_id": ev["id"]})
    assert r.status_code == 200 and r.json()["verification_evidence_id"] == ev["id"]
    other_case = make(owner, "/cases", title="Different case here")
    other_ev = make(owner, f"/cases/{other_case['id']}/evidence", kind="note", title="Other")
    assert owner.patch(f"/tasks/{t['id']}", json={"verification_evidence_id": other_ev["id"]}).status_code == 422
