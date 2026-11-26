"""RAG: document_chunks (tenant-scoped, RLS) holding chunk text + embedding

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE document_chunks (
        id           uuid NOT NULL DEFAULT gen_random_uuid(),
        tenant_id    varchar(64) NOT NULL REFERENCES tenants(id),
        document_id  uuid NOT NULL,
        chunk_index  integer NOT NULL CHECK (chunk_index >= 0),
        content      text NOT NULL,
        embedding    real[] NOT NULL,
        embedder     varchar(64) NOT NULL,
        created_at   timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant_id, id),
        UNIQUE (tenant_id, document_id, chunk_index),
        FOREIGN KEY (tenant_id, document_id) REFERENCES documents (tenant_id, id) ON DELETE CASCADE
    );
    CREATE INDEX ix_document_chunks_doc ON document_chunks (tenant_id, document_id);
    ALTER TABLE document_chunks ENABLE ROW LEVEL SECURITY;
    ALTER TABLE document_chunks FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON document_chunks
        USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
        WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));
    GRANT SELECT, INSERT, DELETE ON document_chunks TO eai_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS document_chunks CASCADE")
