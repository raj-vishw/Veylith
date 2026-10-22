"""Week 3: case severity, task verification, evidence provenance and retention, report job lifecycle

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cases", sa.Column("severity", sa.String(10), server_default="", nullable=False))
    op.create_check_constraint("ck_cases_severity", "cases", "severity IN ('','low','medium','high','critical')")

    # Completed (a claim) and Verified (a check by someone) are separate facts on a remediation task.
    op.add_column("tasks", sa.Column("verification_status", sa.String(20), server_default="unverified", nullable=False))
    op.add_column("tasks", sa.Column("verified_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("tasks", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tasks", sa.Column("verification_notes", sa.Text(), server_default="", nullable=False))
    op.add_column("tasks", sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_check_constraint("ck_tasks_verification", "tasks", "verification_status IN ('unverified','verified','rejected')")

    # Evidence: when it was collected (analyst-stated), and soft deletion so the object and its audit trail survive.
    op.add_column("evidence", sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("evidence", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("evidence", sa.Column("deleted_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("evidence", sa.Column("deletion_reason", sa.Text(), server_default="", nullable=False))

    # Report jobs: queued -> processing -> completed | failed, with a safe error category instead of raw exception text.
    op.add_column("reports", sa.Column("template_version", sa.String(20), server_default="1", nullable=False))
    op.add_column("reports", sa.Column("error_code", sa.String(40), server_default="", nullable=False))
    op.add_column("reports", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("reports", sa.Column("attempts", sa.Integer(), server_default="0", nullable=False))
    op.execute("UPDATE reports SET status='queued' WHERE status='pending'")
    op.execute("UPDATE reports SET status='completed' WHERE status='ready'")
    op.execute("UPDATE reports SET error_code='render_failed' WHERE status='failed'")
    op.create_check_constraint("ck_reports_status", "reports", "status IN ('queued','processing','completed','failed')")


def downgrade() -> None:
    op.drop_constraint("ck_reports_status", "reports")
    op.execute("UPDATE reports SET status='pending' WHERE status IN ('queued','processing')")
    op.execute("UPDATE reports SET status='ready' WHERE status='completed'")
    for c in ("attempts", "started_at", "error_code", "template_version"):
        op.drop_column("reports", c)
    for c in ("deletion_reason", "deleted_by", "deleted_at", "collected_at"):
        op.drop_column("evidence", c)
    op.drop_constraint("ck_tasks_verification", "tasks")
    for c in ("created_by", "verification_notes", "verified_at", "verified_by", "verification_status"):
        op.drop_column("tasks", c)
    op.drop_constraint("ck_cases_severity", "cases")
    op.drop_column("cases", "severity")
