"""Week 2, Day 8: the exposure graph API (schema, bounds, cycles, determinism, filters, authorization)."""
import uuid

from .helpers import make, rel, scenario


def ids(graph):
    return [n["id"] for n in graph["nodes"]]


def test_graph_schema_nodes_and_edges(owner):
    s = scenario(owner)
    g = owner.get("/graph").json()
    asset = next(n for n in g["nodes"] if n["id"] == f"asset-{s['storefront']['id']}")
    assert asset["type"] == "asset" and asset["label"] == "storefront-api" and asset["criticality"] == "critical"
    assert asset["verification_status"] == "unverified"  # real value from the database, not a placeholder
    uses = next(e for e in g["edges"] if e["type"] == "USES_VENDOR")
    assert {"id", "source", "target", "type", "verification_status", "access_scope", "has_evidence", "derived"} <= set(uses)
    assert g["generated_at"] and g["max_nodes"] <= 400


def test_edge_evidence_indicator_reflects_recorded_evidence(owner):
    s = scenario(owner)
    r = rel(owner, "vendor", s["acme"]["id"], "HAS_ACCESS_TO", "asset", s["storefront"]["id"], evidence="OAuth app audit 2026-09", access_scope="read:repo")
    g = owner.get(f"/graph?vendor_id={s['acme']['id']}").json()
    edge = next(e for e in g["edges"] if e["id"] == f"rel-{r['id']}")
    assert edge["has_evidence"] is True
    plain = next(e for e in g["edges"] if e["type"] == "USES_VENDOR")
    assert plain["has_evidence"] is False


def test_viewers_do_not_see_access_scope_or_evidence_text(owner, viewer):
    s = scenario(owner)
    r = rel(owner, "vendor", s["acme"]["id"], "HAS_ACCESS_TO", "asset", s["storefront"]["id"], evidence="secret audit note", access_scope="admin:everything")
    analyst_edge = next(e for e in owner.get("/graph").json()["edges"] if e["id"] == f"rel-{r['id']}")
    viewer_graph = viewer.get("/graph").json()
    viewer_edge = next(e for e in viewer_graph["edges"] if e["id"] == f"rel-{r['id']}")
    assert analyst_edge["access_scope"] == "admin:everything" and viewer_edge["access_scope"] == "" and viewer_edge["has_evidence"] is True
    detail = viewer.get(f"/graph/edges/rel-{r['id']}").json()
    assert detail["access_scope"] == "" and detail["evidence"] == "" and detail["has_evidence"] is True
    assert "admin:everything" not in viewer.get(f"/graph/nodes/vendor-{s['acme']['id']}").text
    assert "secret audit note" not in viewer.get("/relationships").text
    assert owner.get(f"/graph/edges/rel-{r['id']}").json()["evidence"] == "secret audit note"


def test_node_type_filter(owner):
    scenario(owner)
    only_vendors = owner.get("/graph?node_type=vendor").json()
    assert only_vendors["nodes"] and {n["type"] for n in only_vendors["nodes"]} == {"vendor"} and only_vendors["edges"] == []
    two = owner.get("/graph?node_type=client,asset").json()
    assert {n["type"] for n in two["nodes"]} == {"client", "asset"}
    assert owner.get("/graph?node_type=toaster").status_code == 422


def test_filters_apply_independently(owner):
    s = scenario(owner)
    assert {n["label"] for n in owner.get("/graph?criticality=critical&node_type=asset").json()["nodes"]} == {"storefront-api"}
    assert all(e["type"] == "DEPENDS_ON" for e in owner.get("/graph?rel_type=DEPENDS_ON").json()["edges"])
    verified = owner.get("/graph?verification_status=verified").json()["edges"]
    assert verified and all(e["verification_status"] == "verified" for e in verified)
    assert {n["label"] for n in owner.get("/graph?q=retail").json()["nodes"]} == {"Retail Client"}
    clinic = owner.get(f"/graph?client_id={s['clinic']['id']}").json()
    assert "storefront-api" not in {n["label"] for n in clinic["nodes"]}


def test_neighborhood_is_bounded_in_depth_and_size(owner):
    s = scenario(owner)
    center = f"vendor-{s['acme']['id']}"
    d1 = owner.get(f"/graph/neighborhood/{center}?max_depth=1").json()
    d3 = owner.get(f"/graph/neighborhood/{center}?max_depth=3").json()
    assert center in ids(d1) and len(d3["nodes"]) > len(d1["nodes"])
    capped = owner.get(f"/graph/neighborhood/{center}?max_depth=3&max_nodes=3").json()
    assert len(capped["nodes"]) <= 3 and capped["truncated"] is True
    kept = set(ids(capped))
    assert all(e["source"] in kept and e["target"] in kept for e in capped["edges"])
    assert owner.get(f"/graph/neighborhood/{center}?max_depth=99").status_code == 422
    assert owner.get(f"/graph/neighborhood/{center}?max_nodes=100000").status_code == 422


def test_cycles_terminate_and_never_duplicate(owner):
    c = make(owner, "/clients", name="Cyclic Client")
    a = [make(owner, "/assets", client_id=c["id"], name=f"svc-{i}", type="production_service") for i in range(3)]
    rel(owner, "asset", a[0]["id"], "DEPENDS_ON", "asset", a[1]["id"])
    rel(owner, "asset", a[1]["id"], "DEPENDS_ON", "asset", a[2]["id"])
    rel(owner, "asset", a[2]["id"], "DEPENDS_ON", "asset", a[0]["id"])  # a three-node cycle
    g = owner.get(f"/graph/neighborhood/asset-{a[0]['id']}?max_depth=4").json()
    assert len(set(ids(g))) == len(ids(g)) == 4  # three assets + their client, each exactly once
    edge_ids = [e["id"] for e in g["edges"]]
    assert len(edge_ids) == len(set(edge_ids))
    assert owner.get(f"/graph/path?from=asset-{a[0]['id']}&to=asset-{a[2]['id']}").json()["found"] is True


def test_duplicate_relationships_cannot_create_duplicate_edges(owner):
    s = scenario(owner)
    again = owner.post("/relationships", json=dict(source_type="client", source_id=s["retail"]["id"], target_type="vendor", target_id=s["acme"]["id"], rel_type="USES_VENDOR"))
    assert again.status_code == 409
    edges = [e["id"] for e in owner.get("/graph").json()["edges"]]
    assert len(edges) == len(set(edges))


def test_response_is_deterministic(owner):
    scenario(owner)
    a, b = owner.get("/graph").json(), owner.get("/graph").json()
    for g in (a, b):
        g.pop("generated_at")
    assert a == b
    labels = [(n["type"], n["label"].lower()) for n in a["nodes"]]
    assert labels == sorted(labels)


def test_depth_limit_is_enforced_on_the_main_graph_endpoint(owner):
    s = scenario(owner)
    assert owner.get(f"/graph?focus=vendor-{s['acme']['id']}&max_depth=5").status_code == 422
    assert owner.get(f"/graph?focus=vendor-{s['acme']['id']}&max_depth=2").status_code == 200


# ---- tenant isolation, each endpoint on its own -------------------------------------------------
def test_other_tenant_cannot_use_graph_traversal(owner, other_owner):
    s = scenario(owner)
    foreign_vendor = f"vendor-{s['acme']['id']}"
    assert other_owner.get(f"/graph?focus={foreign_vendor}").status_code == 404
    assert other_owner.get(f"/graph/neighborhood/{foreign_vendor}").status_code == 404
    assert other_owner.get(f"/graph?client_id={s['retail']['id']}").status_code == 404
    assert other_owner.get(f"/graph?vendor_id={s['acme']['id']}").status_code == 404
    mine = make(other_owner, "/vendors", name="Mine")
    assert other_owner.get(f"/graph/path?from={foreign_vendor}&to=vendor-{mine['id']}").status_code == 404


def test_other_tenant_cannot_read_node_or_edge_details(owner, other_owner):
    s = scenario(owner)
    edge = next(e for e in owner.get("/graph").json()["edges"] if e["id"].startswith("rel-"))
    assert other_owner.get(f"/graph/nodes/vendor-{s['acme']['id']}").status_code == 404
    assert other_owner.get(f"/graph/nodes/asset-{s['storefront']['id']}").status_code == 404
    assert other_owner.get(f"/graph/edges/{edge['id']}").status_code == 404
    assert other_owner.get(f"/graph/nodes/vendor-{uuid.uuid4()}").status_code == 404  # same answer as for a real foreign id


def test_other_tenants_filters_never_surface_foreign_records(owner, other_owner):
    scenario(owner)
    for query in ("", "?criticality=critical", "?q=acme", "?node_type=vendor", "?rel_type=USES_VENDOR", "?verification_status=verified"):
        g = other_owner.get("/graph" + query).json()
        assert g["nodes"] == [] and g["edges"] == [], query
