"""Inventory changes keep assessments current without an analyst having to remember to re-run correlation."""
import pytest

from app.config import get_settings

from .helpers import load_fixtures, make, rel, scenario


@pytest.fixture
def auto(monkeypatch):
    monkeypatch.setattr(get_settings(), "auto_correlate", True)


def test_new_inventory_produces_assessments_automatically(owner, auto):
    load_fixtures()  # advisories already exist when the inventory is recorded afterwards
    assert owner.get("/assessments").json()["total"] == 0
    ids = scenario(owner)
    items = owner.get("/assessments?limit=100").json()["items"]
    assert any(a["advisory"] == "CVE-2099-1001" and a["client"] == "Retail Client" for a in items)


def test_fixing_the_version_withdraws_the_match_automatically(owner, auto):
    load_fixtures()
    ids = scenario(owner)
    owner.patch(f"/products/{ids['agent']['id']}", json={"version": "4.2.1"})
    active = [a for a in owner.get("/assessments?limit=100").json()["items"] if a["advisory"] == "CVE-2099-1001"]
    assert not active


def test_dry_run_csv_does_not_schedule(owner, auto, monkeypatch):
    import io
    from app.services import autocorrelate

    calls = []
    monkeypatch.setattr("app.routers.inventory.schedule_correlation", lambda db, org: calls.append(org))
    owner.post("/vendors/import?dry_run=true", files={"file": ("v.csv", io.BytesIO(b"name\nX\n"), "text/csv")})
    assert calls == []
    owner.post("/vendors/import?dry_run=false", files={"file": ("v.csv", io.BytesIO(b"name\nX\n"), "text/csv")})
    assert len(calls) == 1
