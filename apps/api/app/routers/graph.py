import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..common import get_owned, paginate
from ..deps import Ctx, analyst, viewer
from ..models import Relationship
from ..services import audit
from ..services import graph as gsvc
from ..services.autocorrelate import schedule as schedule_correlation
from ..services.outbox import flush as flush_outbox

router = APIRouter(tags=["graph"])

MAX_NODES = 400


class RelationshipIn(BaseModel):
    source_type: str = Field(pattern="^(client|vendor|product|asset)$")
    source_id: uuid.UUID
    target_type: str = Field(pattern="^(client|vendor|product|asset)$")
    target_id: uuid.UUID
    rel_type: str = Field(pattern="^(USES_VENDOR|CONNECTS_TO|HAS_ACCESS_TO|DEPENDS_ON|HOSTS|MANAGES_FOR)$")
    access_scope: str = Field(default="", max_length=300)
    evidence: str = Field(default="", max_length=5000)
    source: str = Field(default="manual", max_length=100)
    confidence: str = Field(default="medium", pattern="^(low|medium|high)$")
    verification_status: str = Field(default="unverified", pattern="^(unverified|verified|disputed|stale)$")
    verification_method: str = Field(default="", pattern="^(|manual_review|document|api|vendor_confirmation|other)$")


class RelationshipPatch(BaseModel):
    access_scope: str | None = Field(default=None, max_length=300)
    evidence: str | None = Field(default=None, max_length=5000)
    confidence: str | None = Field(default=None, pattern="^(low|medium|high)$")
    verification_status: str | None = Field(default=None, pattern="^(unverified|verified|disputed|stale)$")
    verification_method: str | None = Field(default=None, pattern="^(|manual_review|document|api|vendor_confirmation|other)$")


REL_FIELDS = [
    "id", "source_type", "source_id", "target_type", "target_id", "rel_type", "access_scope", "evidence",
    "source", "confidence", "verification_status", "verification_method", "verified_at", "created_at", "updated_at",
]


def _rel(r: Relationship) -> dict:
    return {f: getattr(r, f) for f in REL_FIELDS}


def _rel_view(ctx: Ctx, r: Relationship) -> dict:
    """Read view of a relationship. Viewers see that it exists and whether it has evidence, not the access scope or evidence text."""
    out = _rel(r)
    if not ctx.can("analyst"):
        out["access_scope"], out["evidence"] = "", ""
    out["has_evidence"] = bool(r.evidence)
    return out


def _require_entity(ctx: Ctx, kind: str, ident: uuid.UUID):
    return get_owned(ctx, gsvc.ENTITY_MODELS[kind], ident)  # 404 if missing, deleted, or another tenant's


@router.post("/relationships", status_code=201)
def create_relationship(body: RelationshipIn, ctx: Ctx = Depends(analyst)):
    if not gsvc.valid_pair(body.rel_type, body.source_type, body.target_type):
        raise HTTPException(status_code=422, detail=f"{body.rel_type} cannot connect a {body.source_type} to a {body.target_type}")
    _require_entity(ctx, body.source_type, body.source_id)
    _require_entity(ctx, body.target_type, body.target_id)
    if body.verification_status == "verified" and not body.verification_method:
        raise HTTPException(status_code=422, detail="A relationship can only be marked verified with a verification method")
    exists = ctx.db.scalar(
        select(Relationship.id).where(
            Relationship.organization_id == ctx.org_id,
            Relationship.source_type == body.source_type, Relationship.source_id == body.source_id,
            Relationship.target_type == body.target_type, Relationship.target_id == body.target_id,
            Relationship.rel_type == body.rel_type,
        )
    )
    if exists:
        raise HTTPException(status_code=409, detail="This relationship already exists")
    r = Relationship(organization_id=ctx.org_id, created_by=ctx.user.id, **body.model_dump())
    if r.verification_status == "verified":
        r.verified_at = datetime.now(UTC)
    ctx.db.add(r)
    ctx.db.flush()
    meta = {"type": r.rel_type, "source": f"{r.source_type}:{r.source_id}", "target": f"{r.target_type}:{r.target_id}"}
    audit.record(ctx.db, ctx.org_id, "relationship.created", actor=ctx.user, object_type="relationship", object_id=r.id, metadata=meta)
    audit.track_change(ctx.db, ctx.org_id, "relationship", r.id, "created", ctx.user, meta)
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _rel(r)


@router.get("/relationships")
def list_relationships(
    rel_type: str | None = None, entity_id: uuid.UUID | None = None, verification_status: str | None = None,
    limit: int = 50, offset: int = 0, ctx: Ctx = Depends(viewer),
):
    stmt = select(Relationship).where(Relationship.organization_id == ctx.org_id)
    if rel_type:
        stmt = stmt.where(Relationship.rel_type == rel_type)
    if verification_status:
        stmt = stmt.where(Relationship.verification_status == verification_status)
    if entity_id:
        stmt = stmt.where((Relationship.source_id == entity_id) | (Relationship.target_id == entity_id))
    return paginate(ctx.db, stmt.order_by(Relationship.created_at.desc()), limit, offset, lambda r: _rel_view(ctx, r))


@router.get("/relationships/{rel_id}")
def get_relationship(rel_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    return _rel_view(ctx, get_owned(ctx, Relationship, rel_id))


@router.patch("/relationships/{rel_id}")
def patch_relationship(rel_id: uuid.UUID, body: RelationshipPatch, ctx: Ctx = Depends(analyst)):
    r = get_owned(ctx, Relationship, rel_id)
    values = body.model_dump(exclude_unset=True, exclude_none=True)
    if values.get("verification_status") == "verified" and not (values.get("verification_method") or r.verification_method):
        raise HTTPException(status_code=422, detail="A relationship can only be marked verified with a verification method")
    changes = audit.diff(r, values)
    for k, v in values.items():
        setattr(r, k, v)
    if values.get("verification_status") == "verified":
        r.verified_at = datetime.now(UTC)
    audit.record(ctx.db, ctx.org_id, "relationship.updated", actor=ctx.user, object_type="relationship", object_id=r.id, metadata=changes)
    audit.track_change(ctx.db, ctx.org_id, "relationship", r.id, "updated", ctx.user, changes)
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _rel(r)


@router.delete("/relationships/{rel_id}", status_code=204)
def delete_relationship(rel_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    r = get_owned(ctx, Relationship, rel_id)
    meta = {"type": r.rel_type, "source": f"{r.source_type}:{r.source_id}", "target": f"{r.target_type}:{r.target_id}"}
    audit.record(ctx.db, ctx.org_id, "relationship.deleted", actor=ctx.user, object_type="relationship", object_id=r.id, metadata=meta)
    audit.track_change(ctx.db, ctx.org_id, "relationship", r.id, "deleted", ctx.user, meta)
    ctx.db.delete(r)
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()


# --------------------------------------------------------------------------- graph views
def _parse_node(value: str) -> tuple[str, uuid.UUID]:
    kind, _, raw = value.partition("-")
    if kind not in gsvc.ENTITY_MODELS:
        raise HTTPException(status_code=422, detail="Invalid node id")
    try:
        return kind, uuid.UUID(raw)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid node id")


@router.get("/graph")
def get_graph(
    client_id: uuid.UUID | None = None,
    vendor_id: uuid.UUID | None = None,
    focus: str | None = Query(default=None, description="Node id to expand around, e.g. vendor-<uuid>"),
    depth: int = Query(default=1, ge=1, le=4, description="Deprecated alias of max_depth"),
    max_depth: int | None = Query(default=None, ge=1, le=4),
    node_type: str | None = Query(default=None, description="Comma-separated: client,vendor,product,asset"),
    asset_type: str | None = None,
    criticality: str | None = None,
    rel_type: str | None = None,
    verification_status: str | None = None,
    q: str | None = None,
    max_nodes: int = Query(default=MAX_NODES, ge=10, le=MAX_NODES),
    ctx: Ctx = Depends(viewer),
):
    g = gsvc.load_graph(ctx.db, ctx.org_id)
    edges = g.edges()

    nodes: dict[str, dict] = {}
    for kind in ("client", "vendor", "product", "asset"):
        for obj in getattr(g, kind + "s").values():
            nodes[gsvc.node_id(kind, obj.id)] = gsvc.node_payload(kind, obj)

    seeds: set[str] = set()
    if client_id:
        get_owned(ctx, gsvc.ENTITY_MODELS["client"], client_id)
        cid = gsvc.node_id("client", client_id)
        seeds |= {cid} | {gsvc.node_id("asset", a.id) for a in g.assets.values() if a.client_id == client_id}
    if vendor_id:
        get_owned(ctx, gsvc.ENTITY_MODELS["vendor"], vendor_id)
        seeds.add(gsvc.node_id("vendor", vendor_id))
    if focus:
        kind, ident = _parse_node(focus)
        if gsvc.node_id(kind, ident) not in nodes:
            raise HTTPException(status_code=404, detail="Node not found")
        seeds.add(gsvc.node_id(kind, ident))
    hit_cap = False
    if seeds:
        keep, hit_cap = gsvc.bounded_neighborhood(edges, seeds, max_depth or depth, max_nodes)
        nodes = {k: v for k, v in nodes.items() if k in keep}
    if node_type:
        wanted = {t.strip() for t in node_type.split(",") if t.strip()}
        if not wanted <= set(gsvc.ENTITY_MODELS):
            raise HTTPException(status_code=422, detail="node_type must be a comma-separated list of: client, vendor, product, asset")
        nodes = {k: v for k, v in nodes.items() if v["type"] in wanted}

    if asset_type:
        nodes = {k: v for k, v in nodes.items() if v["type"] != "asset" or v.get("subtype") == asset_type}
    if criticality:
        nodes = {k: v for k, v in nodes.items() if v.get("criticality") in (None, criticality)}
    if q:
        needle = q.lower()
        nodes = {k: v for k, v in nodes.items() if needle in v["label"].lower()}
    if rel_type:
        edges = [e for e in edges if e["type"] == rel_type]
    if verification_status:
        edges = [e for e in edges if e["verification_status"] == verification_status]

    ordered = sorted(nodes.values(), key=lambda n: (n["type"], n["label"].lower(), n["id"]))  # deterministic output
    truncated = hit_cap or len(ordered) > max_nodes
    ordered = ordered[:max_nodes]
    kept = {n["id"] for n in ordered}
    # Every returned edge must connect two returned nodes; duplicates cannot occur (one row per relationship id).
    edges = sorted((e for e in edges if e["source"] in kept and e["target"] in kept), key=lambda e: (e["type"], e["id"]))
    return {"nodes": ordered, "edges": _present_edges(ctx, edges), "truncated": truncated, "node_count": len(ordered), "edge_count": len(edges),
            "max_nodes": max_nodes, "generated_at": datetime.now(UTC)}


def _present_edges(ctx: Ctx, edges: list[dict]) -> list[dict]:
    """Edge metadata is only as visible as the caller's role: viewers see the relationship, not its access scope."""
    if ctx.can("analyst"):
        return edges
    return [{**e, "access_scope": ""} for e in edges]


@router.get("/graph/neighborhood/{node}")
def neighborhood(node: str, max_depth: int = Query(default=1, ge=1, le=4), max_nodes: int = Query(default=100, ge=1, le=MAX_NODES), ctx: Ctx = Depends(viewer)):
    """Nodes connected to one node within a bounded depth and size (used to expand the graph progressively)."""
    kind, ident = _parse_node(node)
    _require_entity(ctx, kind, ident)  # 404 for another tenant's id
    g = gsvc.load_graph(ctx.db, ctx.org_id)
    edges = g.edges()
    order, truncated = gsvc.bounded_neighborhood(edges, {gsvc.node_id(kind, ident)}, max_depth, max_nodes)
    payloads = {}
    for k in ("client", "vendor", "product", "asset"):
        for obj in getattr(g, k + "s").values():
            nid = gsvc.node_id(k, obj.id)
            if nid in order:
                payloads[nid] = gsvc.node_payload(k, obj)
    kept = set(payloads)
    out_edges = sorted((e for e in edges if e["source"] in kept and e["target"] in kept), key=lambda e: (e["type"], e["id"]))
    return {
        "center": gsvc.node_id(kind, ident), "depth": max_depth, "truncated": truncated,
        "nodes": sorted(payloads.values(), key=lambda n: (n["type"], n["label"].lower(), n["id"])), "edges": _present_edges(ctx, out_edges),
    }


@router.get("/graph/nodes/{node}")
def node_detail(node: str, ctx: Ctx = Depends(viewer)):
    kind, ident = _parse_node(node)
    obj = _require_entity(ctx, kind, ident)
    g = gsvc.load_graph(ctx.db, ctx.org_id)
    nid = gsvc.node_id(kind, ident)
    incident = [e for e in g.edges() if nid in (e["source"], e["target"])]
    attrs = {c.name: getattr(obj, c.name) for c in obj.__table__.columns if c.name not in ("organization_id", "deleted_at")}
    detail = {"node": gsvc.node_payload(kind, obj), "attributes": attrs, "edges": _present_edges(ctx, incident)}
    if kind == "vendor":
        detail["blast_radius"] = gsvc.blast_radius(g, ident)["summary"]
    return detail


@router.get("/graph/edges/{edge_id}")
def edge_detail(edge_id: str, ctx: Ctx = Depends(viewer)):
    if not edge_id.startswith("rel-"):
        raise HTTPException(status_code=404, detail="Only recorded relationships have detail")
    try:
        rid = uuid.UUID(edge_id[4:])
    except ValueError:
        raise HTTPException(status_code=404, detail="Edge not found")
    return _rel_view(ctx, get_owned(ctx, Relationship, rid))


@router.get("/graph/path")
def graph_path(from_node: str = Query(alias="from"), to_node: str = Query(alias="to"), ctx: Ctx = Depends(viewer)):
    """Trace the recorded relationship path between two entities, e.g. a vendor and a critical asset."""
    for n in (from_node, to_node):
        kind, ident = _parse_node(n)
        _require_entity(ctx, kind, ident)
    g = gsvc.load_graph(ctx.db, ctx.org_id)
    path = gsvc.shortest_path(g.edges(), from_node, to_node)
    return {"found": path is not None, "edges": path or []}


@router.get("/vendors/{vendor_id}/blast-radius")
def vendor_blast_radius(vendor_id: uuid.UUID, product_id: uuid.UUID | None = None, ctx: Ctx = Depends(viewer)):
    get_owned(ctx, gsvc.ENTITY_MODELS["vendor"], vendor_id)
    if product_id:
        get_owned(ctx, gsvc.ENTITY_MODELS["product"], product_id)
    return gsvc.blast_radius(gsvc.load_graph(ctx.db, ctx.org_id), vendor_id, product_id)


@router.get("/analysis/concentration")
def concentration(min_clients: int = 2, ctx: Ctx = Depends(viewer)):
    """Structural concentration only: shared dependencies in the recorded graph, not outage probability."""
    items = [i for i in gsvc.concentration(gsvc.load_graph(ctx.db, ctx.org_id)) if i["client_count"] >= min_clients]
    return {"items": items}
