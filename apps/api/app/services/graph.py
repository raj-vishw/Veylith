"""Exposure graph: relationship rules, traversal, blast radius and vendor concentration.

PostgreSQL remains the source of truth; the graph is a view over entity and relationship tables."""

import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Asset, Client, Product, Relationship, Vendor

ENTITY_MODELS = {"client": Client, "vendor": Vendor, "product": Product, "asset": Asset}

# relationship type -> allowed (source type, target type) pairs
RELATIONSHIP_RULES: dict[str, list[tuple[str, str]]] = {
    "USES_VENDOR": [("client", "vendor")],
    "CONNECTS_TO": [("vendor", "asset"), ("asset", "asset"), ("vendor", "vendor")],
    "HAS_ACCESS_TO": [("vendor", "asset"), ("product", "asset")],
    "DEPENDS_ON": [("asset", "product"), ("asset", "vendor"), ("asset", "asset"), ("vendor", "vendor"), ("product", "product")],
    "HOSTS": [("asset", "asset"), ("vendor", "asset")],
    "MANAGES_FOR": [("vendor", "client")],
}

# Derived edges come from foreign keys (recorded data), and are not editable relationships.
DERIVED = ("SUPPLIED_BY", "BELONGS_TO")


def node_id(kind: str, ident) -> str:
    return f"{kind}-{ident}"


def valid_pair(rel_type: str, source_type: str, target_type: str) -> bool:
    return (source_type, target_type) in RELATIONSHIP_RULES.get(rel_type, [])


@dataclass
class Graph:
    clients: dict = field(default_factory=dict)
    vendors: dict = field(default_factory=dict)
    products: dict = field(default_factory=dict)
    assets: dict = field(default_factory=dict)
    rels: list = field(default_factory=list)

    def entity(self, kind: str, ident):
        return getattr(self, kind + "s").get(ident)

    def edges(self) -> list[dict]:
        """All edges (recorded relationships + derived foreign-key edges) between entities that exist."""
        out = []
        for r in self.rels:
            if self.entity(r.source_type, r.source_id) is None or self.entity(r.target_type, r.target_id) is None:
                continue
            out.append(
                {
                    "id": f"rel-{r.id}",
                    "source": node_id(r.source_type, r.source_id),
                    "target": node_id(r.target_type, r.target_id),
                    "type": r.rel_type,
                    "derived": False,
                    "verification_status": r.verification_status,
                    "confidence": r.confidence,
                    "access_scope": r.access_scope,
                    "has_evidence": bool(r.evidence),
                }
            )
        for p in self.products.values():
            if p.vendor_id in self.vendors:
                out.append(_derived(f"supplied-{p.id}", "product", p.id, "vendor", p.vendor_id, "SUPPLIED_BY"))
        for a in self.assets.values():
            if a.client_id in self.clients:
                out.append(_derived(f"belongs-{a.id}", "asset", a.id, "client", a.client_id, "BELONGS_TO"))
        return out


def _derived(eid, st, sid, tt, tid, rel_type) -> dict:
    return {
        "id": eid, "source": node_id(st, sid), "target": node_id(tt, tid), "type": rel_type, "derived": True,
        "verification_status": "verified", "confidence": "high", "access_scope": "", "has_evidence": False,
    }


def load_graph(db: Session, org_id: uuid.UUID) -> Graph:
    g = Graph()
    g.clients = {c.id: c for c in db.scalars(select(Client).where(Client.organization_id == org_id, Client.archived_at.is_(None)))}
    g.vendors = {v.id: v for v in db.scalars(select(Vendor).where(Vendor.organization_id == org_id, Vendor.deleted_at.is_(None)))}
    g.products = {p.id: p for p in db.scalars(select(Product).where(Product.organization_id == org_id, Product.deleted_at.is_(None)))}
    g.assets = {a.id: a for a in db.scalars(select(Asset).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None)))}
    g.rels = list(db.scalars(select(Relationship).where(Relationship.organization_id == org_id)))
    return g


def adjacency(edges: list[dict]) -> dict[str, list[dict]]:
    adj = defaultdict(list)
    for e in edges:
        adj[e["source"]].append(e)
        adj[e["target"]].append(e)
    return adj


def other_end(edge: dict, nid: str) -> str:
    return edge["target"] if edge["source"] == nid else edge["source"]


def neighborhood(edges: list[dict], seeds: set[str], depth: int) -> set[str]:
    adj = adjacency(edges)
    seen = set(seeds)
    frontier = set(seeds)
    for _ in range(depth):
        nxt = set()
        for n in frontier:
            for e in adj.get(n, []):
                m = other_end(e, n)
                if m not in seen:
                    seen.add(m)
                    nxt.add(m)
        frontier = nxt
    return seen


def bounded_neighborhood(edges: list[dict], seeds: set[str], depth: int, max_nodes: int) -> tuple[list[str], bool]:
    """Breadth-first expansion limited in both depth and size. Deterministic (neighbours are visited in sorted order),
    visits every node once (cycles terminate) and reports whether the size cap cut the result short."""
    adj = adjacency(edges)
    order: list[str] = sorted(seeds)[:max_nodes]
    seen = set(order)
    truncated = len(seeds) > max_nodes
    frontier = list(order)
    for _ in range(depth):
        nxt: list[str] = []
        for n in frontier:
            for m in sorted({other_end(e, n) for e in adj.get(n, [])}):
                if m in seen:
                    continue
                if len(order) >= max_nodes:
                    truncated = True
                    return order, truncated
                seen.add(m)
                order.append(m)
                nxt.append(m)
        frontier = nxt
    return order, truncated


def shortest_path(edges: list[dict], start: str, goal: str, max_depth: int = 6) -> list[dict] | None:
    """Breadth-first shortest path over recorded relationships (treated as undirected for tracing)."""
    adj = adjacency(edges)
    queue: deque[tuple[str, list[dict]]] = deque([(start, [])])
    seen = {start}
    while queue:
        n, path = queue.popleft()
        if n == goal:
            return path
        if len(path) >= max_depth:
            continue
        for e in adj.get(n, []):
            m = other_end(e, n)
            if m not in seen:
                seen.add(m)
                queue.append((m, path + [e]))
    return None


def node_payload(kind: str, obj) -> dict:
    base = {"id": node_id(kind, obj.id), "type": kind, "entity_id": obj.id, "label": obj.name}
    if kind == "asset":
        base.update(subtype=obj.type, criticality=obj.criticality, client_id=obj.client_id, environment=obj.environment, verification_status=obj.verification_status)
    elif kind == "vendor":
        base.update(criticality=obj.criticality, access_level=obj.access_level, review_status=obj.review_status)
    elif kind == "client":
        base.update(criticality=obj.criticality)
    elif kind == "product":
        base.update(version=obj.version)
    return base


# --------------------------------------------------------------------------- blast radius
_SENSITIVE_ACCESS = {"write", "admin"}


def _asset_is_sensitive(a: Asset) -> bool:
    return a.criticality in ("high", "critical") or a.data_sensitivity in ("confidential", "restricted")


def blast_radius(g: Graph, vendor_id: uuid.UUID, product_id: uuid.UUID | None = None) -> dict:
    """Which clients and assets are connected to a vendor (optionally one of its products), and how.

    Direct = recorded dependency on the vendor/product. Downstream = reached through another vendor
    that depends on this one. Nothing here claims compromise: it separates what the graph records
    from what still needs verification."""
    vendor = g.vendors.get(vendor_id)
    if vendor is None:
        return {"vendor": None, "clients": [], "summary": {}}
    product_ids = {product_id} if product_id else {p.id for p in g.products.values() if p.vendor_id == vendor_id}

    per_client: dict[uuid.UUID, dict] = {}

    def entry(client_id, relation: str = "direct") -> dict | None:
        c = g.clients.get(client_id)
        if c is None:
            return None
        return per_client.setdefault(
            client_id,
            {"client_id": c.id, "client": c.name, "relation": relation, "via": [], "assets": {}, "sensitive_access": False,
             "relationships": [], "all_verified": True, "has_asset_level_data": False},
        )

    def note(e: dict | None, r: Relationship, label: str):
        if e is None:
            return
        e["relationships"].append({"id": r.id, "type": r.rel_type, "verification_status": r.verification_status, "label": label})
        if r.verification_status != "verified":
            e["all_verified"] = False

    def add_asset(e: dict | None, asset: Asset, r: Relationship, label: str):
        if e is None:
            return
        slot = e["assets"].setdefault(asset.id, {"asset_id": asset.id, "name": asset.name, "type": asset.type, "criticality": asset.criticality, "internet_exposed": asset.internet_exposed, "rel_types": []})
        slot["rel_types"].append(r.rel_type)
        e["has_asset_level_data"] = True
        note(e, r, label)
        if r.rel_type in ("HAS_ACCESS_TO", "CONNECTS_TO") and (vendor.access_level in _SENSITIVE_ACCESS or _asset_is_sensitive(asset)):
            e["sensitive_access"] = True

    def process_vendor(vid: uuid.UUID, relation: str, via: str | None, prods: set[uuid.UUID]):
        v = g.vendors.get(vid)
        for r in g.rels:
            if r.rel_type == "USES_VENDOR" and r.target_type == "vendor" and r.target_id == vid:
                e = entry(r.source_id, relation)
                if e is not None:
                    e["via"].append(via or v.name)
                    note(e, r, f"{g.clients[r.source_id].name} uses {v.name}")
            elif r.rel_type == "DEPENDS_ON" and r.source_type == "asset" and (
                (r.target_type == "vendor" and r.target_id == vid) or (r.target_type == "product" and r.target_id in prods)
            ):
                a = g.assets.get(r.source_id)
                if a:
                    e = entry(a.client_id, relation)
                    if e is not None:
                        e["via"].append(via or v.name)
                    add_asset(e, a, r, f"{a.name} depends on {v.name}")
            elif r.rel_type in ("HAS_ACCESS_TO", "CONNECTS_TO", "HOSTS") and r.target_type == "asset" and (
                (r.source_type == "vendor" and r.source_id == vid) or (r.source_type == "product" and r.source_id in prods)
            ):
                a = g.assets.get(r.target_id)
                if a:
                    e = entry(a.client_id, relation)
                    if e is not None:
                        e["via"].append(via or v.name)
                    add_asset(e, a, r, f"{v.name} {r.rel_type.lower().replace('_', ' ')} {a.name}")
            elif r.rel_type == "MANAGES_FOR" and r.source_type == "vendor" and r.source_id == vid:
                e = entry(r.target_id, relation)
                if e is not None:
                    e["via"].append(via or v.name)
                    note(e, r, f"{v.name} manages services for {g.clients[r.target_id].name}")

    process_vendor(vendor_id, "direct", None, product_ids)

    # Downstream: vendors recorded as depending on this vendor, and the clients they serve.
    downstream_vendors = {r.source_id for r in g.rels if r.rel_type == "DEPENDS_ON" and r.source_type == "vendor" and r.target_type == "vendor" and r.target_id == vendor_id and r.source_id in g.vendors}
    for dv in downstream_vendors:
        process_vendor(dv, "downstream", f"{g.vendors[dv].name} (depends on {vendor.name})", {p.id for p in g.products.values() if p.vendor_id == dv})

    clients = []
    for e in per_client.values():
        e["via"] = sorted(set(e["via"]))
        e["assets"] = list(e["assets"].values())
        # Only a client reached with no asset-level information can't be assessed beyond "uses the vendor".
        e["insufficient_data"] = not e["has_asset_level_data"]
        e["checklist"] = _checklist(e, vendor)
        del e["has_asset_level_data"]
        clients.append(e)
    clients.sort(key=lambda c: (not c["sensitive_access"], c["relation"] != "direct", c["insufficient_data"], c["client"]))

    summary = {
        "clients_with_recorded_dependency": len(clients),
        "direct_clients": sum(1 for c in clients if c["relation"] == "direct"),
        "downstream_clients": sum(1 for c in clients if c["relation"] == "downstream"),
        "clients_with_sensitive_access": sum(1 for c in clients if c["sensitive_access"]),
        "clients_needing_more_information": sum(1 for c in clients if c["insufficient_data"]),
        "assets_requiring_verification": sum(
            1 for c in clients for a in c["assets"]
        ),
        "unverified_relationships": sum(1 for c in clients for r in c["relationships"] if r["verification_status"] != "verified"),
    }
    return {"vendor": {"id": vendor.id, "name": vendor.name, "access_level": vendor.access_level}, "clients": clients, "summary": summary}


def _checklist(entry: dict, vendor: Vendor) -> list[str]:
    steps = [f"Confirm {entry['client']} actually uses {vendor.name} in its current environment."]
    if entry["insufficient_data"]:
        steps.append("Record which assets use or are accessed by this vendor; the inventory cannot support an assessment yet.")
    for a in entry["assets"]:
        steps.append(f"Verify the deployed version and exposure for '{a['name']}' ({a['criticality']} criticality).")
    if entry["sensitive_access"]:
        steps.append("Review the vendor's access scope and recent access logs for the sensitive assets.")
    if not entry["all_verified"]:
        steps.append("Verify or correct the unverified relationships listed for this client.")
    steps.append("Document the outcome and update the client inventory.")
    return steps


def concentration(g: Graph) -> list[dict]:
    """Vendors shared across several clients, with how many clients depend on each (structural concentration only)."""
    clients_by_vendor: dict[uuid.UUID, set] = defaultdict(set)
    for r in g.rels:
        if r.rel_type == "USES_VENDOR" and r.source_id in g.clients and r.target_id in g.vendors:
            clients_by_vendor[r.target_id].add(r.source_id)
        elif r.rel_type == "DEPENDS_ON" and r.source_type == "asset" and r.source_id in g.assets:
            client_id = g.assets[r.source_id].client_id
            if r.target_type == "vendor" and r.target_id in g.vendors:
                clients_by_vendor[r.target_id].add(client_id)
            elif r.target_type == "product" and r.target_id in g.products:
                clients_by_vendor[g.products[r.target_id].vendor_id].add(client_id)
    out = []
    for vid, cids in clients_by_vendor.items():
        v = g.vendors.get(vid)
        if v is None:
            continue
        out.append(
            {
                "vendor_id": v.id, "vendor": v.name, "criticality": v.criticality, "access_level": v.access_level,
                "client_count": len(cids), "clients": sorted(g.clients[c].name for c in cids if c in g.clients),
            }
        )
    out.sort(key=lambda x: (-x["client_count"], x["vendor"]))
    return out
