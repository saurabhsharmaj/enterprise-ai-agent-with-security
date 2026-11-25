"""initial schema: tables, constraints, indexes, row-level security, least-privilege grants

Revision ID: 0001
Revises:
"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# Tenant-owned tables that get row-level security (RLS).
RLS_TABLES = ["users", "agents", "agent_tools", "invoices", "purchase_orders", "documents",
              "approval_requests", "audit_logs"]

SCHEMA = r"""
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$ LANGUAGE plpgsql;

-- Tenants -----------------------------------------------------------------------------------
CREATE TABLE tenants (
    id          varchar(64) PRIMARY KEY CHECK (id ~ '^[A-Z0-9_]{1,64}$'),
    name        varchar(200) NOT NULL,
    is_active   boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Users: NO password or credential columns. Keycloak is the only credential store.
-- users.id equals the Keycloak `sub` claim.
CREATE TABLE users (
    id              uuid PRIMARY KEY,
    tenant_id       varchar(64) NOT NULL REFERENCES tenants(id),
    username        varchar(100) NOT NULL,
    email           varchar(255),
    full_name       varchar(200) NOT NULL,
    department      varchar(64) NOT NULL,
    approval_limit  numeric(14,2) NOT NULL DEFAULT 0 CHECK (approval_limit >= 0),
    is_active       boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, username)
);
CREATE INDEX ix_users_tenant ON users (tenant_id);

CREATE TABLE roles (
    id           serial PRIMARY KEY,
    name         varchar(50) NOT NULL UNIQUE,
    description  varchar(255) NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    id           serial PRIMARY KEY,
    name         varchar(100) NOT NULL UNIQUE CHECK (name ~ '^[a-z_]+:[a-z_]+$'),
    description  varchar(255) NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id  integer NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX ix_user_roles_role ON user_roles (role_id);

CREATE TABLE role_permissions (
    role_id        integer NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id  integer NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Agents ------------------------------------------------------------------------------------
CREATE TABLE agents (
    id           varchar(64) NOT NULL CHECK (id ~ '^[A-Z0-9_]{1,64}$'),
    tenant_id    varchar(64) NOT NULL REFERENCES tenants(id),
    name         varchar(200) NOT NULL,
    description  text NOT NULL DEFAULT '',
    enabled      boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE agent_tools (
    tenant_id          varchar(64) NOT NULL,
    agent_id           varchar(64) NOT NULL,
    tool_name          varchar(64) NOT NULL CHECK (tool_name ~ '^[a-z_]{1,64}$'),
    description        text NOT NULL DEFAULT '',
    enabled            boolean NOT NULL DEFAULT true,
    requires_approval  boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, tool_name),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id) ON DELETE CASCADE
);

-- Business data -----------------------------------------------------------------------------
CREATE TABLE invoices (
    id              varchar(32) NOT NULL CHECK (id ~ '^INV-[0-9]{1,12}$'),
    tenant_id       varchar(64) NOT NULL REFERENCES tenants(id),
    vendor          varchar(200) NOT NULL,
    description     text NOT NULL DEFAULT '',
    amount          numeric(14,2) NOT NULL CHECK (amount > 0),
    currency        char(3) NOT NULL DEFAULT 'USD',
    status          varchar(16) NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'PAID')),
    department      varchar(64) NOT NULL,
    classification  varchar(16) NOT NULL DEFAULT 'INTERNAL'
                    CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    owner_id        uuid NOT NULL REFERENCES users(id),
    approved_by     uuid REFERENCES users(id),
    approved_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CHECK ((status = 'APPROVED') = (approved_by IS NOT NULL) OR status = 'PAID')
);
CREATE INDEX ix_invoices_tenant_status ON invoices (tenant_id, status);
CREATE INDEX ix_invoices_owner ON invoices (owner_id);

CREATE TABLE purchase_orders (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       varchar(64) NOT NULL REFERENCES tenants(id),
    po_number       varchar(32) NOT NULL,
    vendor          varchar(200) NOT NULL,
    description     text NOT NULL DEFAULT '',
    amount          numeric(14,2) NOT NULL CHECK (amount > 0),
    currency        char(3) NOT NULL DEFAULT 'USD',
    status          varchar(16) NOT NULL DEFAULT 'SUBMITTED'
                    CHECK (status IN ('SUBMITTED', 'CANCELLED', 'FULFILLED')),
    department      varchar(64) NOT NULL,
    created_by      uuid NOT NULL REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, po_number)
);
CREATE INDEX ix_po_tenant_dept ON purchase_orders (tenant_id, department);

CREATE TABLE documents (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       varchar(64) NOT NULL REFERENCES tenants(id),
    title           varchar(255) NOT NULL,
    body            text NOT NULL DEFAULT '',
    department      varchar(64) NOT NULL,
    classification  varchar(16) NOT NULL DEFAULT 'INTERNAL'
                    CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    owner_id        uuid NOT NULL REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ix_documents_tenant_dept ON documents (tenant_id, department);

-- Human-in-the-loop approval gate -------------------------------------------------------------
-- A high-risk tool call that OPA flags (require_human_approval) is parked here until an ADMIN
-- decides. `args_hash` binds the approval to the exact arguments, so it cannot be replayed on
-- different arguments.
CREATE TABLE approval_requests (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    tenant_id     varchar(64) NOT NULL REFERENCES tenants(id),
    requester_id  uuid NOT NULL REFERENCES users(id),
    agent_id      varchar(64),
    tool_name     varchar(64) NOT NULL,
    resource_type varchar(32) NOT NULL,
    resource_id   varchar(64) NOT NULL,
    arguments     jsonb NOT NULL,
    args_hash     char(64) NOT NULL,
    status        varchar(16) NOT NULL DEFAULT 'PENDING'
                  CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXECUTED', 'EXPIRED')),
    decided_by    uuid REFERENCES users(id),
    decided_at    timestamptz,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ix_approval_requests_status ON approval_requests (tenant_id, status);

-- Audit log: append-only (no UPDATE / DELETE grant for the application role) ---------------------
CREATE TABLE audit_logs (
    id                bigserial PRIMARY KEY,
    audit_id          uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    occurred_at       timestamptz NOT NULL DEFAULT now(),
    user_id           uuid,
    username          varchar(100),
    tenant_id         varchar(64) NOT NULL,
    agent_id          varchar(64),
    tool_name         varchar(64),
    resource_type     varchar(32),
    resource_id       varchar(64),
    action            varchar(32) NOT NULL,
    decision          varchar(8) NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'PENDING')),
    reason            text NOT NULL DEFAULT '',
    execution_status  varchar(16) NOT NULL
                      CHECK (execution_status IN ('SUCCESS', 'FAILED', 'NOT_EXECUTED', 'PENDING_APPROVAL')),
    correlation_id    varchar(64) NOT NULL,
    channel           varchar(16) NOT NULL DEFAULT 'api',
    detail            jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ix_audit_tenant_time ON audit_logs (tenant_id, occurred_at DESC);
CREATE INDEX ix_audit_correlation ON audit_logs (correlation_id);
CREATE INDEX ix_audit_user ON audit_logs (user_id);
"""

UPDATED_AT_TABLES = ["tenants", "users", "roles", "permissions", "agents", "agent_tools", "invoices",
                     "purchase_orders", "documents", "approval_requests"]

GRANTS = r"""
GRANT USAGE ON SCHEMA public TO eai_app;

-- Reference data: read only
GRANT SELECT ON tenants, roles, permissions, role_permissions TO eai_app;

-- Tenant data: row-level security applies on top of these grants
GRANT SELECT, INSERT, UPDATE ON users, agents, agent_tools, invoices, purchase_orders, documents,
      approval_requests TO eai_app;
GRANT SELECT, INSERT, DELETE ON user_roles TO eai_app;
GRANT SELECT, UPDATE ON users TO eai_app;

-- Audit log: append-only. No UPDATE, DELETE or TRUNCATE for the runtime role.
GRANT SELECT, INSERT ON audit_logs TO eai_app;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO eai_app;
"""


def upgrade() -> None:
    op.execute(SCHEMA)
    for table in UPDATED_AT_TABLES:
        op.execute(
            f"CREATE TRIGGER trg_{table}_updated BEFORE UPDATE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION set_updated_at()"
        )

    # Row-level security. The runtime role is not the table owner and has no BYPASSRLS, so these
    # policies apply to every statement it runs. The tenant comes from `SET LOCAL app.tenant_id`,
    # which the backend sets from the VALIDATED token on every transaction. Unset => no rows.
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')) "
            f"WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''))"
        )

    # user_roles has no tenant column: it is only visible for users in the current tenant.
    op.execute("ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE user_roles FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON user_roles "
        "USING (EXISTS (SELECT 1 FROM users u WHERE u.id = user_roles.user_id "
        "AND u.tenant_id = nullif(current_setting('app.tenant_id', true), ''))) "
        "WITH CHECK (EXISTS (SELECT 1 FROM users u WHERE u.id = user_roles.user_id "
        "AND u.tenant_id = nullif(current_setting('app.tenant_id', true), '')))"
    )

    op.execute(GRANTS)


def downgrade() -> None:
    for table in ["audit_logs", "approval_requests", "documents", "purchase_orders", "invoices",
                  "agent_tools", "agents", "role_permissions", "user_roles", "permissions", "roles",
                  "users", "tenants"]:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at()")
