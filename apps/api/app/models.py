import uuid
from datetime import UTC, date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


def pk():
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def org_fk():
    return mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)


def ts(**kw):
    return mapped_column(DateTime(timezone=True), default=utcnow, **kw)


# Tables carrying an organization_id and protected by row-level security (see migration).
TENANT_TABLES: list[str] = []


def tenant(cls):
    TENANT_TABLES.append(cls.__tablename__)
    return cls


# --------------------------------------------------------------------------- identity
class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = pk()
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | disabled | pending
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[uuid.UUID] = pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    retention_days: Mapped[int] = mapped_column(Integer, default=365)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | suspended
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "organization_id"),)
    id: Mapped[uuid.UUID] = pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[uuid.UUID] = org_fk()
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # owner | analyst | viewer
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | revoked
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


class AuthSession(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = pk()
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)  # sha256 of the cookie value
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = ts()
    last_seen_at: Mapped[datetime] = ts()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------- inventory
@tenant
class Client(Base):
    __tablename__ = "clients"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    industry: Mapped[str] = mapped_column(String(100), default="")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    owner: Mapped[str] = mapped_column(String(200), default="")  # internal owner / responsible team
    notes: Mapped[str] = mapped_column(Text, default="")
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class Vendor(Base):
    __tablename__ = "vendors"
    __table_args__ = (Index("ix_vendors_org_domain", "organization_id", "domain"),)
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    website: Mapped[str] = mapped_column(String(300), default="")
    domain: Mapped[str] = mapped_column(String(253), default="")
    category: Mapped[str] = mapped_column(String(100), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    owner: Mapped[str] = mapped_column(String(200), default="")
    integration_type: Mapped[str] = mapped_column(String(100), default="")
    access_level: Mapped[str] = mapped_column(String(20), default="none")  # none|read|write|admin
    review_status: Mapped[str] = mapped_column(String(20), default="unreviewed")
    last_reviewed_at: Mapped[date | None] = mapped_column(Date)
    notes: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(100), default="manual")
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    aliases: Mapped[list] = mapped_column(JSONB, default=list)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class Product(Base):
    """A vendor product (with version) recorded in the inventory; the unit advisories are matched against."""

    __tablename__ = "products"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    vendor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vendors.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(100), default="")
    cpe: Mapped[str] = mapped_column(String(400), default="")
    package_name: Mapped[str] = mapped_column(String(200), default="")
    ecosystem: Mapped[str] = mapped_column(String(20), default="generic")  # generic | pypi | npm | semver: selects version semantics
    aliases: Mapped[list] = mapped_column(JSONB, default=list)
    source: Mapped[str] = mapped_column(String(100), default="manual")
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    client_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[str] = mapped_column(String(40), nullable=False)  # repository|cloud_account|application|environment|service_account|other
    environment: Mapped[str] = mapped_column(String(40), default="production")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    data_sensitivity: Mapped[str] = mapped_column(String(20), default="internal")
    product_name: Mapped[str] = mapped_column(String(200), default="")
    product_version: Mapped[str] = mapped_column(String(100), default="")
    source: Mapped[str] = mapped_column(String(100), default="manual")
    verification_status: Mapped[str] = mapped_column(String(20), default="unverified")
    description: Mapped[str] = mapped_column(Text, default="")
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class Relationship(Base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("organization_id", "source_type", "source_id", "target_type", "target_id", "rel_type", name="uq_relationship"),
        Index("ix_rel_source", "organization_id", "source_type", "source_id"),
        Index("ix_rel_target", "organization_id", "target_type", "target_id"),
    )
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rel_type: Mapped[str] = mapped_column(String(30), nullable=False)
    access_scope: Mapped[str] = mapped_column(String(300), default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(100), default="manual")
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    verification_status: Mapped[str] = mapped_column(String(20), default="unverified")  # unverified|verified|disputed|stale
    verification_method: Mapped[str] = mapped_column(String(30), default="")  # manual_review | document | api | vendor_confirmation | other
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class ChangeEvent(Base):
    """Basic change history for inventory records (before/after snapshots)."""

    __tablename__ = "change_events"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    object_type: Mapped[str] = mapped_column(String(30), index=True)
    object_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    action: Mapped[str] = mapped_column(String(20))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    changes: Mapped[dict] = mapped_column(JSONB, default=dict)
    occurred_at: Mapped[datetime] = ts()


@tenant
class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_label: Mapped[str] = mapped_column(String(320), default="")  # user email, or "system"
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    object_type: Mapped[str] = mapped_column(String(40), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    occurred_at: Mapped[datetime] = ts(index=True)
    event_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)


# --------------------------------------------------------------------------- global intelligence (public data)
class SourceRecord(Base):
    """Original upstream payload, kept apart from the normalised advisory fields."""

    __tablename__ = "source_records"
    __table_args__ = (UniqueConstraint("source", "external_id"),)
    id: Mapped[uuid.UUID] = pk()
    source: Mapped[str] = mapped_column(String(30), nullable=False)  # nvd | kev | fixture
    external_id: Mapped[str] = mapped_column(String(100), nullable=False)
    source_url: Mapped[str] = mapped_column(String(500), default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)
    retrieved_at: Mapped[datetime] = ts()


class Advisory(Base):
    __tablename__ = "advisories"
    id: Mapped[uuid.UUID] = pk()
    advisory_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)  # e.g. CVE-2025-0001
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str] = mapped_column(String(500), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str] = mapped_column(String(20), default="unknown")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_added_at: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    mitigation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSONB, default=list)
    source_url: Mapped[str] = mapped_column(String(500), default="")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = ts()
    last_ingested_at: Mapped[datetime] = ts()
    content_hash: Mapped[str] = mapped_column(String(64), default="")


class AdvisoryRevision(Base):
    __tablename__ = "advisory_revisions"
    id: Mapped[uuid.UUID] = pk()
    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), index=True)
    changed_at: Mapped[datetime] = ts()
    changes: Mapped[dict] = mapped_column(JSONB, default=dict)


class AffectedProduct(Base):
    __tablename__ = "affected_products"
    __table_args__ = (Index("ix_affected_norm", "vendor_norm", "product_norm"),)
    id: Mapped[uuid.UUID] = pk()
    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), index=True)
    cpe: Mapped[str] = mapped_column(String(400), default="")
    vendor: Mapped[str] = mapped_column(String(200), default="")
    product: Mapped[str] = mapped_column(String(200), default="")
    vendor_norm: Mapped[str] = mapped_column(String(200), default="")
    product_norm: Mapped[str] = mapped_column(String(200), default="")
    exact_version: Mapped[str] = mapped_column(String(100), default="")
    start_including: Mapped[str] = mapped_column(String(100), default="")
    start_excluding: Mapped[str] = mapped_column(String(100), default="")
    end_including: Mapped[str] = mapped_column(String(100), default="")
    end_excluding: Mapped[str] = mapped_column(String(100), default="")
    vulnerable: Mapped[bool] = mapped_column(Boolean, default=True)


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"
    id: Mapped[uuid.UUID] = pk()
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="running")  # running|succeeded|failed
    started_at: Mapped[datetime] = ts()
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_seen: Mapped[int] = mapped_column(Integer, default=0)
    records_new: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0)
    catalog_version: Mapped[str] = mapped_column(String(100), default="")  # upstream catalogue marker (CISA KEV)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------- assessments
@tenant
class CorrelationRun(Base):
    __tablename__ = "correlation_runs"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    status: Mapped[str] = mapped_column(String(20), default="running")
    started_at: Mapped[datetime] = ts()
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    advisories_considered: Mapped[int] = mapped_column(Integer, default=0)
    assessments_created: Mapped[int] = mapped_column(Integer, default=0)
    assessments_updated: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")


@tenant
class AdvisoryMatch(Base):
    """Evidence that an inventory product matches an advisory. Stored separately from impact assessments so the
    matcher can be re-run, compared across versions, and corrected by an analyst without losing why it fired."""

    __tablename__ = "advisory_matches"
    __table_args__ = (UniqueConstraint("organization_id", "advisory_id", "product_id", name="uq_advisory_match"),)
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), index=True)
    product_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"), index=True)
    vendor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vendors.id", ondelete="CASCADE"))
    method: Mapped[str] = mapped_column(String(20), nullable=False)  # cpe | name | alias | fuzzy
    matcher_version: Mapped[str] = mapped_column(String(20), default="")
    observed_version: Mapped[str] = mapped_column(String(100), default="")
    affected_range: Mapped[dict] = mapped_column(JSONB, default=dict)
    version_status: Mapped[str] = mapped_column(String(20), nullable=False)  # in_range | out_of_range | unknown | unsupported
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # matched | needs_review | insufficient_data | no_match | incorrect
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    incorrect_reason: Mapped[str] = mapped_column(Text, default="")
    marked_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    matched_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class ImpactAssessment(Base):
    __tablename__ = "impact_assessments"
    __table_args__ = (
        Index("ix_assess_org_state", "organization_id", "state"),
        UniqueConstraint("organization_id", "advisory_id", "product_id", "client_id", name="uq_assessment_scope", postgresql_nulls_not_distinct=True),
    )
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), index=True)
    product_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"), index=True)
    vendor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vendors.id", ondelete="CASCADE"))
    client_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    # potential_impact | insufficient_data | confirmed_dependency | exposure_verified | compromise_confirmed | no_match_found
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    match_type: Mapped[str] = mapped_column(String(20), nullable=False)  # cpe | alias | fuzzy
    version_status: Mapped[str] = mapped_column(String(20), nullable=False)  # in_range | unknown | out_of_range
    source_confidence: Mapped[str] = mapped_column(String(10), default="medium")
    match_confidence: Mapped[str] = mapped_column(String(10), default="medium")
    relationship_confidence: Mapped[str] = mapped_column(String(10), default="low")
    impact_confidence: Mapped[str] = mapped_column(String(10), default="low")
    priority: Mapped[str] = mapped_column(String(10), default="low")
    priority_factors: Mapped[list] = mapped_column(JSONB, default=list)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    unknowns: Mapped[list] = mapped_column(JSONB, default=list)
    recommended_steps: Mapped[list] = mapped_column(JSONB, default=list)
    review_status: Mapped[str] = mapped_column(String(20), default="unreviewed")  # unreviewed|reviewed|dismissed
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    advisory_hash: Mapped[str] = mapped_column(String(64), default="")
    # Separate dimensions (the single `state` above is a derived summary kept in sync by derive_state()).
    match_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("advisory_matches.id", ondelete="SET NULL"), index=True)
    match_status: Mapped[str] = mapped_column(String(20), default="matched")  # matched | needs_review | insufficient_data | no_match
    exposure_status: Mapped[str] = mapped_column(String(20), default="unverified")  # unverified | verified | not_applicable
    compromise_status: Mapped[str] = mapped_column(String(20), default="unknown")  # unknown | suspected | confirmed | not_confirmed
    remediation_status: Mapped[str] = mapped_column(String(20), default="not_started")  # not_started | in_progress | completed | verified
    dependency_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    matcher_version: Mapped[str] = mapped_column(String(20), default="")
    path_relationship_ids: Mapped[list] = mapped_column(JSONB, default=list)
    last_evaluated_at: Mapped[datetime] = ts()
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class AssessmentEvidence(Base):
    """Structured, point-in-time evidence behind an assessment. Rows are superseded, never edited or deleted,
    so the reasoning behind an earlier conclusion survives later inventory or advisory changes."""

    __tablename__ = "assessment_evidence"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("impact_assessments.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)  # advisory | source_record | product | relationship | asset | analyst_note
    ref_id: Mapped[str] = mapped_column(String(64), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    snapshot: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = ts()
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OutboxEvent(Base):
    """Transactional outbox: background work is recorded in the same transaction as the change that needs it,
    then dispatched to the broker by a dispatcher. A crash or Redis outage cannot lose or duplicate-trigger it silently."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        Index("ix_outbox_pending", "available_at", postgresql_where=text("dispatched_at IS NULL")),
        Index("uq_outbox_pending_dedupe", "dedupe_key", unique=True, postgresql_where=text("dispatched_at IS NULL AND dedupe_key <> ''")),
    )
    id: Mapped[uuid.UUID] = pk()
    task: Mapped[str] = mapped_column(String(120), nullable=False)
    args: Mapped[list] = mapped_column(JSONB, default=list)
    queue: Mapped[str] = mapped_column(String(30), default="default")
    dedupe_key: Mapped[str] = mapped_column(String(200), default="")
    available_at: Mapped[datetime] = ts()
    created_at: Mapped[datetime] = ts()
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(Text, default="")


@tenant
class AssessmentEvent(Base):
    __tablename__ = "assessment_events"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("impact_assessments.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(40))
    from_state: Mapped[str] = mapped_column(String(30), default="")
    to_state: Mapped[str] = mapped_column(String(30), default="")
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    note: Mapped[str] = mapped_column(Text, default="")
    occurred_at: Mapped[datetime] = ts()


# --------------------------------------------------------------------------- investigations
@tenant
class Case(Base):
    __tablename__ = "cases"
    __table_args__ = (UniqueConstraint("organization_id", "number"),)
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    client_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("clients.id", ondelete="SET NULL"), index=True)
    advisory_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("advisories.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(String(10), default="medium")
    severity: Mapped[str] = mapped_column(String(10), default="")  # impact if the exposure is real; priority is the response order
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    due_date: Mapped[date | None] = mapped_column(Date)
    closure_reason: Mapped[str] = mapped_column(String(30), default="")
    resolution_summary: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class CaseAssessment(Base):
    __tablename__ = "case_assessments"
    __table_args__ = (UniqueConstraint("case_id", "assessment_id"),)
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("impact_assessments.id", ondelete="CASCADE"))


@tenant
class CaseNote(Base):
    __tablename__ = "case_notes"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    body: Mapped[str] = mapped_column(Text, nullable=False)
    visibility: Mapped[str] = mapped_column(String(10), default="internal")  # internal | customer
    created_at: Mapped[datetime] = ts()


@tenant
class CaseEvent(Base):
    """Investigation timeline. is_system separates automated events from human actions."""

    __tablename__ = "case_events"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    summary: Mapped[str] = mapped_column(Text, default="")
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
    occurred_at: Mapped[datetime] = ts()


@tenant
class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    priority: Mapped[str] = mapped_column(String(10), default="medium")
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|in_progress|blocked|done|cancelled
    completion_notes: Mapped[str] = mapped_column(Text, default="")
    verification_evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Completed is a claim by the doer; verification records that someone checked it.
    verification_status: Mapped[str] = mapped_column(String(20), default="unverified")  # unverified|verified|rejected
    verified_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts(onupdate=utcnow)


@tenant
class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("impact_assessments.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(10), nullable=False)  # url | file | note
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    source_name: Mapped[str] = mapped_column(String(200), default="")
    source_url: Mapped[str] = mapped_column(String(1000), default="")
    excerpt: Mapped[str] = mapped_column(Text, default="")
    storage_key: Mapped[str] = mapped_column(String(100), default="")
    original_filename: Mapped[str] = mapped_column(String(300), default="")
    content_type: Mapped[str] = mapped_column(String(100), default="")
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    verification_status: Mapped[str] = mapped_column(String(20), default="unverified")
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    added_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    retrieved_at: Mapped[datetime] = ts()  # when Veylith recorded it
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # when the analyst says it was collected
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    deletion_reason: Mapped[str] = mapped_column(Text, default="")


@tenant
class Report(Base):
    __tablename__ = "reports"
    id: Mapped[uuid.UUID] = pk()
    organization_id: Mapped[uuid.UUID] = org_fk()
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="technical")  # technical | executive
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|processing|completed|failed
    storage_key: Mapped[str] = mapped_column(String(100), default="")
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    error: Mapped[str] = mapped_column(Text, default="")  # internal detail; never returned by the API
    error_code: Mapped[str] = mapped_column(String(40), default="")
    template_version: Mapped[str] = mapped_column(String(20), default="1")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = ts()
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
