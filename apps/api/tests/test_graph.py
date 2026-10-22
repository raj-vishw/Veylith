from .helpers import make, rel, scenario


def node_ids(graph):
    return {n["id"] for n in graph["nodes"]}


def test_graph_contains_entities_and_derived_edges(owner):
    ids = scenario(owner)
    g = owner.get("/graph").json()
    assert f"vendor-{ids['acme']['id']}" in node_ids(g) and f"asset-{ids['storefront']['id']}" in node_ids(g)
    types = {e["type"] for e in g["edges"]}
    assert {"USES_VENDOR", "DEPENDS_ON", "SUPPLIED_BY", "BELONGS_TO"} <= types
    derived = [e for e in g["edges"] if e["derived"]]
    assert derived and all(not e["id"].startswith("rel-") for e in derived)


def test_every_edge_connects_visible_nodes_under_any_filter(owner):
    ids = scenario(owner)
    for query in ("", f"?client_id={ids['retail']['id']}", "?asset_type=repository", "?criticality=critical", "?q=acme", "?rel_type=USES_VENDOR", f"?focus=vendor-{ids['acme']['id']}&depth=2", "?max_nodes=10"):
        g = owner.get("/graph" + query).json()
        nodes = node_ids(g)
        assert all(e["source"] in nodes and e["target"] in nodes for e in g["edges"]), query


def test_filter_by_client_scopes_the_subgraph(owner):
    ids = scenario(owner)
    g = owner.get(f"/graph?client_id={ids['clinic']['id']}").json()
    labels = {n["label"] for n in g["nodes"]}
    assert "Clinic Client" in labels and "intranet" in labels
    assert "storefront-api" not in labels


def test_progressive_expansion_around_a_node(owner):
    ids = scenario(owner)
    one = owner.get(f"/graph?focus=asset-{ids['storefront']['id']}&depth=1").json()
    two = owner.get(f"/graph?focus=asset-{ids['storefront']['id']}&depth=2").json()
    assert len(two["nodes"]) > len(one["nodes"]) >= 3


def test_graph_size_is_capped(owner):
    for i in range(30):
        make(owner, "/vendors", name=f"Vendor {i}")
    g = owner.get("/graph?max_nodes=10").json()
    assert g["truncated"] is True and len(g["nodes"]) == 10
    assert owner.get("/graph?max_nodes=100000").status_code == 422


def test_deleted_entities_disappear_without_dangling_edges(owner):
    ids = scenario(owner)
    owner.delete(f"/vendors/{ids['acme']['id']}")
    g = owner.get("/graph").json()
    assert f"vendor-{ids['acme']['id']}" not in node_ids(g)
    assert all(ids["acme"]["id"] not in (e["source"] + e["target"]) for e in g["edges"])


def test_node_and_edge_detail(owner):
    ids = scenario(owner)
    detail = owner.get(f"/graph/nodes/vendor-{ids['acme']['id']}").json()
    assert detail["attributes"]["name"] == "Acme Analytics Inc." and detail["edges"]
    assert "organization_id" not in detail["attributes"]
    assert detail["blast_radius"]["clients_with_recorded_dependency"] == 2
    edge = next(e for e in owner.get("/graph").json()["edges"] if e["type"] == "DEPENDS_ON")
    assert owner.get(f"/graph/edges/{edge['id']}").json()["rel_type"] == "DEPENDS_ON"
    assert owner.get("/graph/edges/supplied-xyz").status_code == 404
    assert owner.get("/graph/nodes/banana-123").status_code == 422


def test_path_trace_between_vendor_and_critical_asset(owner):
    ids = scenario(owner)
    r = owner.get(f"/graph/path?from=vendor-{ids['acme']['id']}&to=asset-{ids['storefront']['id']}").json()
    assert r["found"] and 1 <= len(r["edges"]) <= 3
    none = owner.get(f"/graph/path?from=vendor-{ids['umbrella']['id']}&to=asset-{ids['storefront']['id']}").json()
    assert none["found"] is False


def test_blast_radius_distinguishes_dependency_from_sensitive_access(owner):
    """An MSP with several clients on one provider: only some granted it access to sensitive systems."""
    provider = make(owner, "/vendors", name="Shared SaaS", access_level="write")
    sensitive_asset_clients = []
    for i in range(5):
        c = make(owner, "/clients", name=f"Client {i}")
        rel(owner, "client", c["id"], "USES_VENDOR", "vendor", provider["id"], verification_status="verified")
        if i < 2:
            a = make(owner, "/assets", client_id=c["id"], name=f"repo-{i}", type="repository", criticality="critical")
            rel(owner, "vendor", provider["id"], "HAS_ACCESS_TO", "asset", a["id"], verification_status="verified")
            sensitive_asset_clients.append(c["id"])
    br = owner.get(f"/vendors/{provider['id']}/blast-radius").json()
    s = br["summary"]
    assert s["clients_with_recorded_dependency"] == 5  # all five depend on it ...
    assert s["clients_with_sensitive_access"] == 2     # ... but only two have the sensitive access relationship
    assert s["clients_needing_more_information"] == 3  # no asset-level data: cannot conclude more than "uses the vendor"
    sensitive = [c for c in br["clients"] if c["sensitive_access"]]
    assert {c["client_id"] for c in sensitive} == set(sensitive_asset_clients)
    assert br["clients"][0]["sensitive_access"]  # most consequential first
    assert all(c["checklist"] for c in br["clients"])


def test_blast_radius_separates_direct_and_downstream(owner):
    upstream = make(owner, "/vendors", name="Upstream Auth")
    reseller = make(owner, "/vendors", name="Reseller App")
    direct, indirect = make(owner, "/clients", name="Direct Client"), make(owner, "/clients", name="Indirect Client")
    rel(owner, "client", direct["id"], "USES_VENDOR", "vendor", upstream["id"])
    rel(owner, "client", indirect["id"], "USES_VENDOR", "vendor", reseller["id"])
    rel(owner, "vendor", reseller["id"], "DEPENDS_ON", "vendor", upstream["id"])
    br = owner.get(f"/vendors/{upstream['id']}/blast-radius").json()
    relation = {c["client"]: c["relation"] for c in br["clients"]}
    assert relation == {"Direct Client": "direct", "Indirect Client": "downstream"}
    assert br["summary"]["downstream_clients"] == 1


def test_blast_radius_flags_unverified_relationships(owner):
    ids = scenario(owner)
    br = owner.get(f"/vendors/{ids['acme']['id']}/blast-radius").json()
    clinic = next(c for c in br["clients"] if c["client"] == "Clinic Client")
    assert clinic["all_verified"] is False and br["summary"]["unverified_relationships"] >= 1


def test_blast_radius_recalculates_when_dependencies_change(owner):
    ids = scenario(owner)
    before = owner.get(f"/vendors/{ids['acme']['id']}/blast-radius").json()["summary"]["clients_with_recorded_dependency"]
    third = make(owner, "/clients", name="Third Client")
    rel(owner, "client", third["id"], "USES_VENDOR", "vendor", ids["acme"]["id"])
    assert owner.get(f"/vendors/{ids['acme']['id']}/blast-radius").json()["summary"]["clients_with_recorded_dependency"] == before + 1


def test_concentration_finds_shared_vendors(owner):
    ids = scenario(owner)
    items = owner.get("/analysis/concentration").json()["items"]
    assert items[0]["vendor"].startswith("Acme") and items[0]["client_count"] == 2
    assert all(i["client_count"] >= 2 for i in items)
