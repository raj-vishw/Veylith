"""row-level security, runtime grants, append-only audit log

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

# Every table that carries organization_id. Kept explicit so a new tenant table is a deliberate decision.
TENANT_TABLES = [
    "clients", "vendors", "products", "assets", "relationships", "change_events", "audit_events",
    "correlation_runs", "impact_assessments", "assessment_events", "cases", "case_assessments",
    "case_notes", "case_events", "tasks", "evidence", "reports",
]


def upgrade() -> None:
    # Runtime role: DML only; no DDL and no ability to bypass RLS (set in the init script).
    op.execute("GRANT USAGE ON SCHEMA public TO veylith_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO veylith_app")
    op.execute("REVOKE ALL ON alembic_version FROM veylith_app")
    op.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO veylith_app")

    # Rows are visible only when they belong to the organization bound to the current transaction
    # (app.org_id). With no organization bound the policy matches nothing.
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"""CREATE POLICY tenant_isolation ON {table}
                USING (organization_id = nullif(current_setting('app.org_id', true), '')::uuid)
                WITH CHECK (organization_id = nullif(current_setting('app.org_id', true), '')::uuid)"""
        )

    # The audit log is append-only for the application: no UPDATE or DELETE privilege, plus a trigger
    # as a second barrier. (Cascade deletes of an organization run as the schema owner.)
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM veylith_app")
    op.execute(
        """CREATE FUNCTION audit_events_immutable() RETURNS trigger AS $$
           BEGIN
             IF current_user = 'veylith_app' THEN
               RAISE EXCEPTION 'audit_events is append-only';
             END IF;
             RETURN COALESCE(OLD, NEW);
           END $$ LANGUAGE plpgsql"""
    )
    op.execute(
        """CREATE TRIGGER audit_events_no_change BEFORE UPDATE OR DELETE ON audit_events
           FOR EACH ROW EXECUTE FUNCTION audit_events_immutable()"""
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_change ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS audit_events_immutable()")
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
