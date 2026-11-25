from sqlalchemy import text
from sqlalchemy.orm import Session


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def search(db: Session, tenant_id: str, query: str, limit: int = 200) -> list[dict]:
    rows = db.execute(
        text("SELECT id, tenant_id, title, body, department, classification, owner_id, created_at "
             "FROM documents WHERE tenant_id = :t AND (title ILIKE :q ESCAPE '\\' OR body ILIKE :q ESCAPE '\\') "
             "ORDER BY created_at DESC, title LIMIT :limit"),
        {"t": tenant_id, "q": _like(query), "limit": limit},
    ).mappings().all()
    return [dict(r) for r in rows]
