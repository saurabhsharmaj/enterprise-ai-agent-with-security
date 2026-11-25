"""Invoice persistence. Every query is tenant-scoped (WHERE tenant_id) AND protected by RLS."""
import uuid
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.orm import Session

_COLS = ("i.id, i.tenant_id, i.vendor, i.description, i.amount, i.currency, i.status, i.department, "
         "i.classification, i.owner_id, ou.username AS owner_username, i.approved_by, i.approved_at, i.created_at")
_FROM = "FROM invoices i JOIN users ou ON ou.id = i.owner_id"


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def get(db: Session, tenant_id: str, invoice_id: str) -> dict | None:
    row = db.execute(
        text(f"SELECT {_COLS} {_FROM} WHERE i.tenant_id = :t AND i.id = :id"),
        {"t": tenant_id, "id": invoice_id},
    ).mappings().first()
    return dict(row) if row else None


def search(db: Session, tenant_id: str, *, status: str | None, owner_id: uuid.UUID | None,
           query: str | None, limit: int = 200) -> list[dict]:
    sql = f"SELECT {_COLS} {_FROM} WHERE i.tenant_id = :t"
    params: dict = {"t": tenant_id, "limit": limit}
    if status:
        sql += " AND i.status = :status"
        params["status"] = status
    if owner_id:
        sql += " AND i.owner_id = :owner"
        params["owner"] = owner_id
    if query:
        sql += " AND (i.vendor ILIKE :q ESCAPE '\\' OR i.description ILIKE :q ESCAPE '\\' OR i.id ILIKE :q ESCAPE '\\')"
        params["q"] = _like(query)
    sql += " ORDER BY i.created_at DESC, i.id LIMIT :limit"
    return [dict(r) for r in db.execute(text(sql), params).mappings().all()]


def approve_atomic(db: Session, tenant_id: str, invoice_id: str, approver_id: uuid.UUID,
                   expected_amount: Decimal) -> dict | None:
    """Single guarded UPDATE: succeeds only if the invoice is STILL pending, STILL has the amount that
    OPA authorised, and is not owned by the approver. Two concurrent approvals => exactly one wins,
    so an invoice can never be approved twice (TOCTOU-safe)."""
    row = db.execute(
        text("UPDATE invoices SET status = 'APPROVED', approved_by = :u, approved_at = now() "
             "WHERE tenant_id = :t AND id = :id AND status = 'PENDING' AND amount = :amt AND owner_id <> :u "
             "RETURNING id, status, approved_at"),
        {"t": tenant_id, "id": invoice_id, "u": approver_id, "amt": expected_amount},
    ).mappings().first()
    return dict(row) if row else None
