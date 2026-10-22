"""account/org/membership status, client/asset/relationship fields from the Week 1 spec

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def _ts(table: str) -> None:
    op.add_column(table, sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))


def upgrade() -> None:
    # users: boolean is_active -> status
    op.add_column("users", sa.Column("status", sa.String(20), server_default="active", nullable=False))
    op.execute("UPDATE users SET status = CASE WHEN is_active THEN 'active' ELSE 'disabled' END")
    op.drop_column("users", "is_active")
    _ts("users")
    op.create_check_constraint("ck_users_status", "users", "status IN ('active','disabled','pending')")

    op.add_column("organizations", sa.Column("status", sa.String(20), server_default="active", nullable=False))
    _ts("organizations")
    op.create_check_constraint("ck_organizations_status", "organizations", "status IN ('active','suspended')")

    op.add_column("memberships", sa.Column("status", sa.String(20), server_default="active", nullable=False))
    _ts("memberships")
    op.create_check_constraint("ck_memberships_status", "memberships", "status IN ('active','revoked')")
    op.create_check_constraint("ck_memberships_role", "memberships", "role IN ('owner','analyst','viewer')")
    op.create_index("ix_memberships_org_user_status", "memberships", ["organization_id", "user_id", "status"])

    op.add_column("clients", sa.Column("owner", sa.String(200), server_default="", nullable=False))
    op.add_column("clients", sa.Column("notes", sa.Text(), server_default="", nullable=False))
    _ts("clients")

    op.add_column("assets", sa.Column("product_name", sa.String(200), server_default="", nullable=False))
    op.add_column("assets", sa.Column("product_version", sa.String(100), server_default="", nullable=False))
    op.add_column("assets", sa.Column("source", sa.String(100), server_default="manual", nullable=False))
    op.add_column("assets", sa.Column("verification_status", sa.String(20), server_default="unverified", nullable=False))
    op.execute(
        "UPDATE assets SET type = CASE type WHEN 'cloud_account' THEN 'cloud_resource' WHEN 'application' THEN 'business_application' "
        "WHEN 'environment' THEN 'production_service' WHEN 'service_account' THEN 'identity' ELSE type END"
    )
    op.create_check_constraint(
        "ck_assets_type",
        "assets",
        "type IN ('repository','cloud_resource','saas_application','business_application','software_package','production_service','identity','other')",
    )

    op.add_column("relationships", sa.Column("verification_method", sa.String(30), server_default="", nullable=False))
    _ts("relationships")
    op.create_check_constraint(
        "ck_relationships_type",
        "relationships",
        "rel_type IN ('USES_VENDOR','CONNECTS_TO','HAS_ACCESS_TO','DEPENDS_ON','HOSTS','MANAGES_FOR')",
    )
    op.create_check_constraint("ck_relationships_verification", "relationships", "verification_status IN ('unverified','verified','disputed','stale')")
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    op.create_index("ix_audit_org_time", "audit_events", ["organization_id", "occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_org_time", "audit_events")
    op.drop_index("ix_sessions_expires_at", "sessions")
    for name, table in (
        ("ck_relationships_verification", "relationships"),
        ("ck_relationships_type", "relationships"),
        ("ck_assets_type", "assets"),
        ("ck_memberships_role", "memberships"),
        ("ck_memberships_status", "memberships"),
        ("ck_organizations_status", "organizations"),
        ("ck_users_status", "users"),
    ):
        op.drop_constraint(name, table)
    op.drop_column("relationships", "updated_at")
    op.drop_column("relationships", "verification_method")
    for col in ("verification_status", "source", "product_version", "product_name"):
        op.drop_column("assets", col)
    for col in ("updated_at", "notes", "owner"):
        op.drop_column("clients", col)
    op.drop_index("ix_memberships_org_user_status", "memberships")
    for table in ("memberships", "organizations"):
        op.drop_column(table, "updated_at")
        op.drop_column(table, "status")
    op.drop_column("users", "updated_at")
    op.add_column("users", sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False))
    op.execute("UPDATE users SET is_active = (status = 'active')")
    op.drop_column("users", "status")
