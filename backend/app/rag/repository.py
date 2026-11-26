from sqlalchemy import text
from sqlalchemy.orm import Session


def replace_chunks(db: Session, tenant_id: str, document_id: str, chunks: list[tuple[int, str, list[float]]],
                   embedder: str) -> None:
    db.execute(text("DELETE FROM document_chunks WHERE tenant_id = :t AND document_id = CAST(:d AS uuid)"),
               {"t": tenant_id, "d": document_id})
    for idx, content, vec in chunks:
        db.execute(text(
            "INSERT INTO document_chunks (tenant_id, document_id, chunk_index, content, embedding, embedder) "
            "VALUES (:t, CAST(:d AS uuid), :i, :c, CAST(:e AS real[]), :m)"),
            {"t": tenant_id, "d": document_id, "i": idx, "c": content, "e": vec, "m": embedder})


def candidates(db: Session, tenant_id: str, embedder: str, limit: int = 4000) -> list[dict]:
    """Chunks of the caller's tenant joined with their PARENT document's authorisation attributes."""
    rows = db.execute(text(
        "SELECT c.chunk_index, c.content, c.embedding, d.id AS document_id, d.tenant_id, d.title, d.department, "
        "d.classification, d.owner_id FROM document_chunks c "
        "JOIN documents d ON d.tenant_id = c.tenant_id AND d.id = c.document_id "
        "WHERE c.tenant_id = :t AND c.embedder = :m ORDER BY d.title, c.chunk_index LIMIT :l"),
        {"t": tenant_id, "m": embedder, "l": limit}).mappings().all()
    return [dict(r) for r in rows]


def get_document(db: Session, tenant_id: str, document_id: str) -> dict | None:
    r = db.execute(text("SELECT id, tenant_id, title, body, department, classification, owner_id FROM documents "
                        "WHERE tenant_id = :t AND id = CAST(:d AS uuid)"), {"t": tenant_id, "d": document_id}).mappings().first()
    return dict(r) if r else None


def list_documents(db: Session, tenant_id: str, limit: int = 500) -> list[dict]:
    rows = db.execute(text(
        "SELECT d.id, d.tenant_id, d.title, d.department, d.classification, d.owner_id, d.created_at, "
        "(SELECT count(*) FROM document_chunks c WHERE c.tenant_id = d.tenant_id AND c.document_id = d.id) AS chunks "
        "FROM documents d WHERE d.tenant_id = :t ORDER BY d.created_at DESC, d.title LIMIT :l"),
        {"t": tenant_id, "l": limit}).mappings().all()
    return [dict(r) for r in rows]


def insert_document(db: Session, tenant_id: str, title: str, body: str, department: str, classification: str,
                    owner_id: str) -> str:
    return str(db.execute(text(
        "INSERT INTO documents (tenant_id, title, body, department, classification, owner_id) "
        "VALUES (:t, :ti, :b, :d, :c, CAST(:o AS uuid)) RETURNING id"),
        {"t": tenant_id, "ti": title, "b": body, "d": department, "c": classification, "o": owner_id}).scalar_one())
