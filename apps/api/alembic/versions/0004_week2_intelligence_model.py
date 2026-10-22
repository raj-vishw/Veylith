"""Week 2: advisory matches, assessment evidence, separate assessment status dimensions, transactional outbox

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

NEW_TENANT_TABLES = ["advisory_matches", "assessment_evidence"]


def _uuid_pk():
    return sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True)


def upgrade() -> None:
    op.add_column("products", sa.Column("ecosystem", sa.String(20), server_default="generic", nullable=False))
    op.create_check_constraint("ck_products_ecosystem", "products", "ecosystem IN ('generic','pypi','npm','semver')")

    op.add_column("ingestion_runs", sa.Column("records_rejected", sa.Integer(), server_default="0", nullable=False))
    op.add_column("ingestion_runs", sa.Column("catalog_version", sa.String(100), server_default="", nullable=False))
    op.add_column("ingestion_runs", sa.Column("attempts", sa.Integer(), server_default="0", nullable=False))
    op.create_check_constraint("ck_ingestion_status", "ingestion_runs", "status IN ('running','succeeded','failed','skipped')")

    op.create_table(
        "advisory_matches",
        _uuid_pk(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("advisory_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("advisories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("products.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vendor_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.String(20), nullable=False),
        sa.Column("matcher_version", sa.String(20), server_default="", nullable=False),
        sa.Column("observed_version", sa.String(100), server_default="", nullable=False),
        sa.Column("affected_range", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("version_status", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("incorrect_reason", sa.Text(), server_default="", nullable=False),
        sa.Column("marked_by", postgresql.UUID(as_uuid=True)),
        sa.Column("matched_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organization_id", "advisory_id", "product_id", name="uq_advisory_match"),
        sa.CheckConstraint("status IN ('matched','needs_review','insufficient_data','no_match','incorrect')", name="ck_match_status"),
        sa.CheckConstraint("method IN ('cpe','name','alias','fuzzy')", name="ck_match_method"),
        sa.CheckConstraint("version_status IN ('in_range','out_of_range','unknown','unsupported')", name="ck_match_version_status"),
    )
    op.create_index("ix_advisory_matches_organization_id", "advisory_matches", ["organization_id"])
    op.create_index("ix_advisory_matches_advisory_id", "advisory_matches", ["advisory_id"])
    op.create_index("ix_advisory_matches_product_id", "advisory_matches", ["product_id"])

    op.add_column("impact_assessments", sa.Column("match_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("advisory_matches.id", ondelete="SET NULL")))
    op.add_column("impact_assessments", sa.Column("match_status", sa.String(20), server_default="matched", nullable=False))
    op.add_column("impact_assessments", sa.Column("exposure_status", sa.String(20), server_default="unverified", nullable=False))
    op.add_column("impact_assessments", sa.Column("compromise_status", sa.String(20), server_default="unknown", nullable=False))
    op.add_column("impact_assessments", sa.Column("remediation_status", sa.String(20), server_default="not_started", nullable=False))
    op.add_column("impact_assessments", sa.Column("dependency_confirmed", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("impact_assessments", sa.Column("assigned_to", postgresql.UUID(as_uuid=True)))
    op.add_column("impact_assessments", sa.Column("matcher_version", sa.String(20), server_default="", nullable=False))
    op.add_column("impact_assessments", sa.Column("path_relationship_ids", postgresql.JSONB(), server_default="[]", nullable=False))
    op.add_column("impact_assessments", sa.Column("last_evaluated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_index("ix_impact_assessments_match_id", "impact_assessments", ["match_id"])
    # Backfill the separate dimensions from the single legacy state.
    op.execute(
        """UPDATE impact_assessments SET
             match_status = CASE WHEN state = 'no_match_found' THEN 'no_match'
                                 WHEN match_type = 'fuzzy' THEN 'needs_review'
                                 WHEN state = 'insufficient_data' THEN 'insufficient_data' ELSE 'matched' END,
             exposure_status = CASE WHEN state IN ('exposure_verified','compromise_confirmed') THEN 'verified' ELSE 'unverified' END,
             compromise_status = CASE WHEN state = 'compromise_confirmed' THEN 'confirmed' ELSE 'unknown' END,
             dependency_confirmed = (state IN ('confirmed_dependency','exposure_verified','compromise_confirmed'))"""
    )
    op.create_check_constraint("ck_assess_match_status", "impact_assessments", "match_status IN ('matched','needs_review','insufficient_data','no_match')")
    op.create_check_constraint("ck_assess_exposure_status", "impact_assessments", "exposure_status IN ('unverified','verified','not_applicable')")
    op.create_check_constraint("ck_assess_compromise_status", "impact_assessments", "compromise_status IN ('unknown','suspected','confirmed','not_confirmed')")
    op.create_check_constraint("ck_assess_remediation_status", "impact_assessments", "remediation_status IN ('not_started','in_progress','completed','verified')")
    op.create_check_constraint("ck_assess_review_status", "impact_assessments", "review_status IN ('unreviewed','reviewed','dismissed')")

    op.create_table(
        "assessment_evidence",
        _uuid_pk(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("impact_assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("ref_id", sa.String(64), server_default="", nullable=False),
        sa.Column("summary", sa.Text(), server_default="", nullable=False),
        sa.Column("snapshot", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("superseded_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("kind IN ('advisory','source_record','product','relationship','asset','analyst_note')", name="ck_assessment_evidence_kind"),
    )
    op.create_index("ix_assessment_evidence_organization_id", "assessment_evidence", ["organization_id"])
    op.create_index("ix_assessment_evidence_assessment_id", "assessment_evidence", ["assessment_id"])

    op.create_table(
        "outbox_events",
        _uuid_pk(),
        sa.Column("task", sa.String(120), nullable=False),
        sa.Column("args", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("queue", sa.String(30), server_default="default", nullable=False),
        sa.Column("dedupe_key", sa.String(200), server_default="", nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True)),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_error", sa.Text(), server_default="", nullable=False),
    )
    op.create_index("ix_outbox_pending", "outbox_events", ["available_at"], postgresql_where=sa.text("dispatched_at IS NULL"))
    op.create_index("uq_outbox_pending_dedupe", "outbox_events", ["dedupe_key"], unique=True, postgresql_where=sa.text("dispatched_at IS NULL AND dedupe_key <> ''"))

    # Row-level security for the new tenant tables (the runtime role already holds DML grants via default privileges).
    for table in NEW_TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"""CREATE POLICY tenant_isolation ON {table}
                USING (organization_id = nullif(current_setting('app.org_id', true), '')::uuid)
                WITH CHECK (organization_id = nullif(current_setting('app.org_id', true), '')::uuid)"""
        )
    # Evidence rows are append-only for the application: they can be superseded (UPDATE) but never deleted.
    op.execute("REVOKE DELETE ON assessment_evidence FROM veylith_app")


def downgrade() -> None:
    for table in NEW_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
    op.drop_table("outbox_events")
    op.drop_table("assessment_evidence")
    for name in ("ck_assess_review_status", "ck_assess_remediation_status", "ck_assess_compromise_status", "ck_assess_exposure_status", "ck_assess_match_status"):
        op.drop_constraint(name, "impact_assessments")
    op.drop_index("ix_impact_assessments_match_id", "impact_assessments")
    for col in ("last_evaluated_at", "path_relationship_ids", "matcher_version", "assigned_to", "dependency_confirmed", "remediation_status", "compromise_status", "exposure_status", "match_status", "match_id"):
        op.drop_column("impact_assessments", col)
    op.drop_table("advisory_matches")
    op.drop_constraint("ck_ingestion_status", "ingestion_runs")
    for col in ("attempts", "catalog_version", "records_rejected"):
        op.drop_column("ingestion_runs", col)
    op.drop_constraint("ck_products_ecosystem", "products")
    op.drop_column("products", "ecosystem")
