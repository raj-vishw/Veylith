import csv
import io
import re
import uuid
from datetime import date
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from ..common import get_owned, paginate
from ..config import get_settings
from ..deps import Ctx, analyst, viewer
from ..models import Asset, Client, Product, Relationship, Vendor, utcnow
from ..security import enforce_expensive_limit
from ..services import audit
from ..services.autocorrelate import schedule as schedule_correlation
from ..services.outbox import flush as flush_outbox

router = APIRouter(tags=["inventory"])

LEVEL = "^(low|medium|high|critical)$"
ACCESS = "^(none|read|write|admin)$"
CONF = "^(low|medium|high)$"
ASSET_TYPES = "^(repository|cloud_resource|saas_application|business_application|software_package|production_service|identity|other)$"


# --------------------------------------------------------------------------- clients
class ClientIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    industry: str = Field(default="", max_length=100)
    criticality: str = Field(default="medium", pattern=LEVEL)
    owner: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=10000)


class ClientPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    industry: str | None = Field(default=None, max_length=100)
    criticality: str | None = Field(default=None, pattern=LEVEL)
    owner: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=10000)


def _client(c: Client) -> dict:
    return {
        "id": c.id, "name": c.name, "industry": c.industry, "criticality": c.criticality, "owner": c.owner, "notes": c.notes,
        "status": "archived" if c.archived_at else "active", "archived_at": c.archived_at, "created_at": c.created_at, "updated_at": c.updated_at,
    }


@router.get("/clients")
def list_clients(q: str | None = None, include_archived: bool = False, limit: int = 50, offset: int = 0, ctx: Ctx = Depends(viewer)):
    stmt = select(Client).where(Client.organization_id == ctx.org_id)
    if not include_archived:
        stmt = stmt.where(Client.archived_at.is_(None))
    if q:
        stmt = stmt.where(Client.name.ilike(f"%{q}%"))
    return paginate(ctx.db, stmt.order_by(Client.name), limit, offset, _client)


@router.post("/clients", status_code=201)
def create_client(body: ClientIn, ctx: Ctx = Depends(analyst)):
    c = Client(organization_id=ctx.org_id, **body.model_dump())
    ctx.db.add(c)
    ctx.db.flush()
    audit.record(ctx.db, ctx.org_id, "client.created", actor=ctx.user, object_type="client", object_id=c.id, metadata={"name": c.name})
    audit.track_change(ctx.db, ctx.org_id, "client", c.id, "created", ctx.user, body.model_dump())
    ctx.db.commit()
    return _client(c)


@router.get("/clients/{client_id}")
def get_client(client_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    return _client(get_owned(ctx, Client, client_id))


@router.patch("/clients/{client_id}")
def patch_client(client_id: uuid.UUID, body: ClientPatch, ctx: Ctx = Depends(analyst)):
    c = get_owned(ctx, Client, client_id)
    values = body.model_dump(exclude_unset=True, exclude_none=True)
    changes = audit.diff(c, values)
    for k, v in values.items():
        setattr(c, k, v)
    audit.record(ctx.db, ctx.org_id, "client.updated", actor=ctx.user, object_type="client", object_id=c.id, metadata=changes)
    audit.track_change(ctx.db, ctx.org_id, "client", c.id, "updated", ctx.user, changes)
    ctx.db.commit()
    return _client(c)


@router.post("/clients/{client_id}/archive")
def archive_client(client_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    c = get_owned(ctx, Client, client_id)
    c.archived_at = c.archived_at or utcnow()
    audit.record(ctx.db, ctx.org_id, "client.archived", actor=ctx.user, object_type="client", object_id=c.id)
    audit.track_change(ctx.db, ctx.org_id, "client", c.id, "archived", ctx.user, {})
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _client(c)


@router.post("/clients/{client_id}/restore")
def restore_client(client_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    c = get_owned(ctx, Client, client_id)
    c.archived_at = None
    audit.record(ctx.db, ctx.org_id, "client.restored", actor=ctx.user, object_type="client", object_id=c.id)
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _client(c)


# --------------------------------------------------------------------------- vendors
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(value: str) -> str:
    """Returns a bare, lowercased hostname, or '' when the value is not a plausible domain.
    A domain is a lead for identifying a vendor, never proof of identity."""
    value = (value or "").strip().lower()
    if not value:
        return ""
    if "//" not in value:
        value = "//" + value
    host = urlparse(value).hostname or ""
    host = host.removeprefix("www.").rstrip(".")
    return host if _DOMAIN_RE.match(host) else ""


def normalize_website(value: str) -> str:
    domain = normalize_domain(value)
    return f"https://{domain}" if domain else ""


class VendorIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    website: str = Field(default="", max_length=300)
    category: str = Field(default="", max_length=100)
    description: str = Field(default="", max_length=5000)
    criticality: str = Field(default="medium", pattern=LEVEL)
    owner: str = Field(default="", max_length=200)
    integration_type: str = Field(default="", max_length=100)
    access_level: str = Field(default="none", pattern=ACCESS)
    review_status: str = Field(default="unreviewed", pattern="^(unreviewed|in_review|reviewed)$")
    last_reviewed_at: date | None = None
    notes: str = Field(default="", max_length=10000)
    source: str = Field(default="manual", max_length=100)
    confidence: str = Field(default="medium", pattern=CONF)
    aliases: list[str] = Field(default_factory=list, max_length=20)


class VendorPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    website: str | None = Field(default=None, max_length=300)
    category: str | None = Field(default=None, max_length=100)
    description: str | None = Field(default=None, max_length=5000)
    criticality: str | None = Field(default=None, pattern=LEVEL)
    owner: str | None = Field(default=None, max_length=200)
    integration_type: str | None = Field(default=None, max_length=100)
    access_level: str | None = Field(default=None, pattern=ACCESS)
    review_status: str | None = Field(default=None, pattern="^(unreviewed|in_review|reviewed)$")
    last_reviewed_at: date | None = None
    notes: str | None = Field(default=None, max_length=10000)
    source: str | None = Field(default=None, max_length=100)
    confidence: str | None = Field(default=None, pattern=CONF)
    aliases: list[str] | None = Field(default=None, max_length=20)


VENDOR_FIELDS = [
    "id", "name", "website", "domain", "category", "description", "criticality", "owner", "integration_type",
    "access_level", "review_status", "last_reviewed_at", "notes", "source", "confidence", "aliases", "created_at", "updated_at",
]


def _vendor(v: Vendor) -> dict:
    return {f: getattr(v, f) for f in VENDOR_FIELDS}


@router.get("/vendors")
def list_vendors(
    q: str | None = None,
    category: str | None = None,
    criticality: str | None = None,
    client_id: uuid.UUID | None = None,
    review_status: str | None = None,
    sort: str = "name",
    limit: int = 50,
    offset: int = 0,
    ctx: Ctx = Depends(viewer),
):
    stmt = select(Vendor).where(Vendor.organization_id == ctx.org_id, Vendor.deleted_at.is_(None))
    if review_status:
        stmt = stmt.where(Vendor.review_status == review_status)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Vendor.name.ilike(like), Vendor.domain.ilike(like), Vendor.category.ilike(like)))
    if category:
        stmt = stmt.where(Vendor.category == category)
    if criticality:
        stmt = stmt.where(Vendor.criticality == criticality)
    if client_id:
        get_owned(ctx, Client, client_id)
        stmt = stmt.where(
            Vendor.id.in_(
                select(Relationship.target_id).where(
                    Relationship.organization_id == ctx.org_id,
                    Relationship.rel_type == "USES_VENDOR",
                    Relationship.source_type == "client",
                    Relationship.source_id == client_id,
                )
            )
        )
    order = {"name": func.lower(Vendor.name).asc(), "-name": func.lower(Vendor.name).desc(), "updated": Vendor.updated_at.desc(), "-updated": Vendor.updated_at.asc()}.get(sort)
    if order is None:
        raise HTTPException(status_code=422, detail="sort must be one of: name, -name, updated, -updated")
    return paginate(ctx.db, stmt.order_by(order), limit, offset, _vendor)


def _vendor_values(data: dict) -> dict:
    values = dict(data)
    if "website" in values and values["website"] is not None:
        raw = values["website"]
        values["domain"] = normalize_domain(raw)
        values["website"] = normalize_website(raw) if raw.strip() else ""
        if raw.strip() and not values["domain"]:
            raise HTTPException(status_code=422, detail="website is not a valid domain")
    return values


@router.post("/vendors", status_code=201)
def create_vendor(body: VendorIn, ctx: Ctx = Depends(analyst)):
    values = _vendor_values(body.model_dump())
    dup = ctx.db.scalar(
        select(Vendor.id).where(
            Vendor.organization_id == ctx.org_id,
            Vendor.deleted_at.is_(None),
            or_(func.lower(Vendor.name) == values["name"].lower(), (Vendor.domain == values["domain"]) if values["domain"] else False),
        )
    )
    if dup:
        raise HTTPException(status_code=409, detail="A vendor with this name or domain already exists")
    v = Vendor(organization_id=ctx.org_id, **values)
    ctx.db.add(v)
    ctx.db.flush()
    audit.record(ctx.db, ctx.org_id, "vendor.created", actor=ctx.user, object_type="vendor", object_id=v.id, metadata={"name": v.name})
    audit.track_change(ctx.db, ctx.org_id, "vendor", v.id, "created", ctx.user, {"name": v.name})
    ctx.db.commit()
    return _vendor(v)


@router.get("/vendors/{vendor_id}")
def get_vendor(vendor_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    v = get_owned(ctx, Vendor, vendor_id)
    out = _vendor(v)
    out["products"] = [
        _product(p)
        for p in ctx.db.scalars(select(Product).where(Product.organization_id == ctx.org_id, Product.vendor_id == v.id, Product.deleted_at.is_(None)).order_by(Product.name))
    ]
    return out


@router.patch("/vendors/{vendor_id}")
def patch_vendor(vendor_id: uuid.UUID, body: VendorPatch, ctx: Ctx = Depends(analyst)):
    v = get_owned(ctx, Vendor, vendor_id)
    values = _vendor_values(body.model_dump(exclude_unset=True, exclude_none=True))
    changes = audit.diff(v, values)
    for k, val in values.items():
        setattr(v, k, val)
    audit.record(ctx.db, ctx.org_id, "vendor.updated", actor=ctx.user, object_type="vendor", object_id=v.id, metadata=changes)
    audit.track_change(ctx.db, ctx.org_id, "vendor", v.id, "updated", ctx.user, changes)
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _vendor(v)


@router.delete("/vendors/{vendor_id}", status_code=204)
def delete_vendor(vendor_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    """Soft delete: the record is hidden but audit history and past assessments keep their references."""
    v = get_owned(ctx, Vendor, vendor_id)
    v.deleted_at = utcnow()
    audit.record(ctx.db, ctx.org_id, "vendor.deleted", actor=ctx.user, object_type="vendor", object_id=v.id, metadata={"name": v.name})
    audit.track_change(ctx.db, ctx.org_id, "vendor", v.id, "deleted", ctx.user, {})
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()


# ---- CSV import ------------------------------------------------------------
CSV_COLUMNS = ["name", "website", "category", "criticality", "owner", "integration_type", "access_level", "description"]
_LEVELS = {"low", "medium", "high", "critical"}
_ACCESS = {"none", "read", "write", "admin"}


def parse_vendor_csv(text: str, existing_names: set[str], existing_domains: set[str]) -> dict:
    s = get_settings()
    reader = csv.DictReader(io.StringIO(text))
    headers = [h.strip().lower() for h in (reader.fieldnames or [])]
    if "name" not in headers:
        raise HTTPException(status_code=422, detail="CSV must include a 'name' column")
    unknown = [h for h in headers if h not in CSV_COLUMNS]
    reader.fieldnames = headers
    accepted, rejected, duplicates = [], [], []
    seen_names, seen_domains = set(), set()
    for i, row in enumerate(reader, start=2):
        if i - 1 > s.max_csv_rows:
            raise HTTPException(status_code=422, detail=f"CSV exceeds {s.max_csv_rows} rows")
        row = {k: (v or "").strip() for k, v in row.items() if k in CSV_COLUMNS}
        errors = []
        name = row.get("name", "")
        if not name or len(name) > 200:
            errors.append("name is required (max 200 characters)")
        domain = ""
        if row.get("website"):
            domain = normalize_domain(row["website"])
            if not domain:
                errors.append("website is not a valid domain")
        crit = row.get("criticality", "").lower() or "medium"
        if crit not in _LEVELS:
            errors.append("criticality must be low, medium, high or critical")
        access = row.get("access_level", "").lower() or "none"
        if access not in _ACCESS:
            errors.append("access_level must be none, read, write or admin")
        if errors:
            rejected.append({"row": i, "name": name, "errors": errors})
            continue
        key = name.lower()
        if key in existing_names or (domain and domain in existing_domains) or key in seen_names or (domain and domain in seen_domains):
            duplicates.append({"row": i, "name": name, "domain": domain})
            continue
        seen_names.add(key)
        if domain:
            seen_domains.add(domain)
        accepted.append(
            {
                "name": name,
                "website": f"https://{domain}" if domain else "",
                "domain": domain,
                "category": row.get("category", "")[:100],
                "criticality": crit,
                "owner": row.get("owner", "")[:200],
                "integration_type": row.get("integration_type", "")[:100],
                "access_level": access,
                "description": row.get("description", "")[:5000],
            }
        )
    return {"accepted": accepted, "rejected": rejected, "duplicates": duplicates, "ignored_columns": unknown}


@router.post("/vendors/import")
async def import_vendors(file: UploadFile = File(...), dry_run: bool = True, ctx: Ctx = Depends(analyst)):
    """dry_run=true returns a preview and changes nothing; dry_run=false commits the accepted rows."""
    enforce_expensive_limit("csv_import", ctx.org_id, ctx.user.id)
    s = get_settings()
    data = await file.read(s.max_csv_bytes + 1)
    if len(data) > s.max_csv_bytes:
        raise HTTPException(status_code=413, detail="CSV file too large")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=422, detail="CSV must be UTF-8 encoded")
    rows = ctx.db.execute(select(Vendor.name, Vendor.domain).where(Vendor.organization_id == ctx.org_id, Vendor.deleted_at.is_(None))).all()
    result = parse_vendor_csv(text, {r.name.lower() for r in rows}, {r.domain for r in rows if r.domain})
    result["dry_run"] = dry_run
    if not dry_run:
        for item in result["accepted"]:
            v = Vendor(organization_id=ctx.org_id, source="csv_import", **item)
            ctx.db.add(v)
        audit.record(
            ctx.db, ctx.org_id, "vendor.csv_imported", actor=ctx.user, object_type="vendor",
            metadata={"filename": (file.filename or "")[:200], "created": len(result["accepted"]), "rejected": len(result["rejected"]), "duplicates": len(result["duplicates"])},
        )
        schedule_correlation(ctx.db, ctx.org_id)
        ctx.db.commit()
        flush_outbox()  # only a real import changes the inventory
    return result


# --------------------------------------------------------------------------- products
class ProductIn(BaseModel):
    vendor_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(default="", max_length=100)
    cpe: str = Field(default="", max_length=400, pattern=r"^(cpe:2\.3:[aho]:.*)?$")
    package_name: str = Field(default="", max_length=200)
    ecosystem: str = Field(default="generic", pattern="^(generic|pypi|npm|semver)$")
    aliases: list[str] = Field(default_factory=list, max_length=20)
    source: str = Field(default="manual", max_length=100)
    confidence: str = Field(default="medium", pattern=CONF)


class ProductPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    version: str | None = Field(default=None, max_length=100)
    cpe: str | None = Field(default=None, max_length=400, pattern=r"^(cpe:2\.3:[aho]:.*)?$")
    package_name: str | None = Field(default=None, max_length=200)
    ecosystem: str | None = Field(default=None, pattern="^(generic|pypi|npm|semver)$")
    aliases: list[str] | None = Field(default=None, max_length=20)
    confidence: str | None = Field(default=None, pattern=CONF)


def _product(p: Product) -> dict:
    return {
        "id": p.id, "vendor_id": p.vendor_id, "name": p.name, "version": p.version, "cpe": p.cpe,
        "package_name": p.package_name, "ecosystem": p.ecosystem, "aliases": p.aliases, "source": p.source, "confidence": p.confidence,
    }


@router.get("/products")
def list_products(vendor_id: uuid.UUID | None = None, q: str | None = None, limit: int = 50, offset: int = 0, ctx: Ctx = Depends(viewer)):
    stmt = select(Product).where(Product.organization_id == ctx.org_id, Product.deleted_at.is_(None))
    if vendor_id:
        stmt = stmt.where(Product.vendor_id == vendor_id)
    if q:
        stmt = stmt.where(Product.name.ilike(f"%{q}%"))
    return paginate(ctx.db, stmt.order_by(Product.name), limit, offset, _product)


@router.post("/products", status_code=201)
def create_product(body: ProductIn, ctx: Ctx = Depends(analyst)):
    get_owned(ctx, Vendor, body.vendor_id)
    p = Product(organization_id=ctx.org_id, **body.model_dump())
    ctx.db.add(p)
    ctx.db.flush()
    audit.record(ctx.db, ctx.org_id, "product.created", actor=ctx.user, object_type="product", object_id=p.id, metadata={"name": p.name, "version": p.version})
    audit.track_change(ctx.db, ctx.org_id, "product", p.id, "created", ctx.user, {"name": p.name, "version": p.version})
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _product(p)


@router.patch("/products/{product_id}")
def patch_product(product_id: uuid.UUID, body: ProductPatch, ctx: Ctx = Depends(analyst)):
    p = get_owned(ctx, Product, product_id)
    values = body.model_dump(exclude_unset=True, exclude_none=True)
    changes = audit.diff(p, values)
    for k, v in values.items():
        setattr(p, k, v)
    audit.record(ctx.db, ctx.org_id, "product.updated", actor=ctx.user, object_type="product", object_id=p.id, metadata=changes)
    audit.track_change(ctx.db, ctx.org_id, "product", p.id, "updated", ctx.user, changes)
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _product(p)


@router.delete("/products/{product_id}", status_code=204)
def delete_product(product_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    p = get_owned(ctx, Product, product_id)
    p.deleted_at = utcnow()
    audit.record(ctx.db, ctx.org_id, "product.deleted", actor=ctx.user, object_type="product", object_id=p.id)
    audit.track_change(ctx.db, ctx.org_id, "product", p.id, "deleted", ctx.user, {})
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()


# --------------------------------------------------------------------------- assets
class AssetIn(BaseModel):
    client_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    type: str = Field(pattern=ASSET_TYPES)
    environment: str = Field(default="production", pattern="^(production|staging|development|other)$")
    criticality: str = Field(default="medium", pattern=LEVEL)
    internet_exposed: bool = False
    data_sensitivity: str = Field(default="internal", pattern="^(public|internal|confidential|restricted)$")
    product_name: str = Field(default="", max_length=200)
    product_version: str = Field(default="", max_length=100)
    source: str = Field(default="manual", max_length=100)
    verification_status: str = Field(default="unverified", pattern="^(unverified|verified|disputed|stale)$")
    description: str = Field(default="", max_length=5000)


class AssetPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    type: str | None = Field(default=None, pattern=ASSET_TYPES)
    environment: str | None = Field(default=None, pattern="^(production|staging|development|other)$")
    criticality: str | None = Field(default=None, pattern=LEVEL)
    internet_exposed: bool | None = None
    data_sensitivity: str | None = Field(default=None, pattern="^(public|internal|confidential|restricted)$")
    product_name: str | None = Field(default=None, max_length=200)
    product_version: str | None = Field(default=None, max_length=100)
    source: str | None = Field(default=None, max_length=100)
    verification_status: str | None = Field(default=None, pattern="^(unverified|verified|disputed|stale)$")
    description: str | None = Field(default=None, max_length=5000)


ASSET_FIELDS = ["id", "client_id", "name", "type", "environment", "criticality", "internet_exposed", "data_sensitivity", "product_name", "product_version", "source", "verification_status", "description", "created_at", "updated_at"]


def _asset(a: Asset) -> dict:
    return {f: getattr(a, f) for f in ASSET_FIELDS}


@router.get("/assets")
def list_assets(
    client_id: uuid.UUID | None = None,
    type: str | None = None,
    criticality: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    ctx: Ctx = Depends(viewer),
):
    stmt = select(Asset).where(Asset.organization_id == ctx.org_id, Asset.deleted_at.is_(None))
    if client_id:
        stmt = stmt.where(Asset.client_id == client_id)
    if type:
        stmt = stmt.where(Asset.type == type)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if q:
        stmt = stmt.where(Asset.name.ilike(f"%{q}%"))
    return paginate(ctx.db, stmt.order_by(Asset.name), limit, offset, _asset)


@router.post("/assets", status_code=201)
def create_asset(body: AssetIn, ctx: Ctx = Depends(analyst)):
    get_owned(ctx, Client, body.client_id)
    a = Asset(organization_id=ctx.org_id, **body.model_dump())
    ctx.db.add(a)
    ctx.db.flush()
    audit.record(ctx.db, ctx.org_id, "asset.created", actor=ctx.user, object_type="asset", object_id=a.id, metadata={"name": a.name, "type": a.type})
    audit.track_change(ctx.db, ctx.org_id, "asset", a.id, "created", ctx.user, {"name": a.name, "type": a.type})
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _asset(a)


@router.get("/assets/{asset_id}")
def get_asset(asset_id: uuid.UUID, ctx: Ctx = Depends(viewer)):
    return _asset(get_owned(ctx, Asset, asset_id))


@router.patch("/assets/{asset_id}")
def patch_asset(asset_id: uuid.UUID, body: AssetPatch, ctx: Ctx = Depends(analyst)):
    a = get_owned(ctx, Asset, asset_id)
    values = body.model_dump(exclude_unset=True, exclude_none=True)
    changes = audit.diff(a, values)
    for k, v in values.items():
        setattr(a, k, v)
    audit.record(ctx.db, ctx.org_id, "asset.updated", actor=ctx.user, object_type="asset", object_id=a.id, metadata=changes)
    audit.track_change(ctx.db, ctx.org_id, "asset", a.id, "updated", ctx.user, changes)
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
    return _asset(a)


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: uuid.UUID, ctx: Ctx = Depends(analyst)):
    a = get_owned(ctx, Asset, asset_id)
    a.deleted_at = utcnow()
    audit.record(ctx.db, ctx.org_id, "asset.deleted", actor=ctx.user, object_type="asset", object_id=a.id, metadata={"name": a.name})
    audit.track_change(ctx.db, ctx.org_id, "asset", a.id, "deleted", ctx.user, {})
    schedule_correlation(ctx.db, ctx.org_id)
    ctx.db.commit()
    flush_outbox()
