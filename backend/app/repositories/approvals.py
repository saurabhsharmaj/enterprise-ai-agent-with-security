"""Human-approval gate storage. A grant is bound to (requester, tool, resource, args_hash) so it
cannot be replayed on different arguments or by a different user, and it expires."""
import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

_COLS = ("a.id, a.tenant_id, a.requester_id, ru.username AS requester_username, a.agent_id, a.tool_name, "
         "a.resource_type, a.resource_id, a.arguments, a.status, a.decided_by, a.decided_at, a.expires_at, a.created_at")
_FROM = "FROM approval_requests a JOIN users ru ON ru.id = a.requester_id"


def create(db: Session, tenant_id: str, *, requester_id: uuid.UUID, agent_id: str | None, tool_name: str,
           resource_type: str, resource_id: str, arguments: dict, args_hash: str, ttl_minutes: int) -> uuid.UUID:
    return db.execute(
        text("INSERT INTO approval_requests (tenant_id, requester_id, agent_id, tool_name, resource_type, "
             "resource_id, arguments, args_hash, expires_at) VALUES (:t, :u, :a, :tool, :rt, :rid, "
             "CAST(:args AS jsonb), :h, :exp) RETURNING id"),
        {"t": tenant_id, "u": requester_id, "a": agent_id, "tool": tool_name, "rt": resource_type,
         "rid": resource_id, "args": json.dumps(arguments, default=str), "h": args_hash,
         "exp": datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)},
    ).scalar_one()


def find(db: Session, tenant_id: str, *, status: str, requester_id: uuid.UUID, tool_name: str,
         resource_type: str, resource_id: str, args_hash: str) -> dict | None:
    row = db.execute(
        text("SELECT id FROM approval_requests WHERE tenant_id = :t AND status = :s AND requester_id = :u "
             "AND tool_name = :tool AND resource_type = :rt AND resource_id = :rid AND args_hash = :h "
             "AND expires_at > now() ORDER BY created_at DESC LIMIT 1"),
        {"t": tenant_id, "s": status, "u": requester_id, "tool": tool_name, "rt": resource_type,
         "rid": resource_id, "h": args_hash}).mappings().first()
    return dict(row) if row else None


def mark_executed(db: Session, tenant_id: str, request_id: uuid.UUID) -> bool:
    """One-time use: an APPROVED request becomes EXECUTED together with the action itself."""
    return db.execute(
        text("UPDATE approval_requests SET status = 'EXECUTED' WHERE tenant_id = :t AND id = :id "
             "AND status = 'APPROVED'"), {"t": tenant_id, "id": request_id}).rowcount == 1


def get(db: Session, tenant_id: str, request_id: uuid.UUID) -> dict | None:
    row = db.execute(text(f"SELECT {_COLS} {_FROM} WHERE a.tenant_id = :t AND a.id = :id"),
                     {"t": tenant_id, "id": request_id}).mappings().first()
    return dict(row) if row else None


def list_requests(db: Session, tenant_id: str, requester_id: uuid.UUID | None, limit: int = 100) -> list[dict]:
    sql = f"SELECT {_COLS} {_FROM} WHERE a.tenant_id = :t"
    params: dict = {"t": tenant_id, "limit": limit}
    if requester_id:
        sql += " AND a.requester_id = :u"
        params["u"] = requester_id
    sql += " ORDER BY a.created_at DESC LIMIT :limit"
    return [dict(r) for r in db.execute(text(sql), params).mappings().all()]


def decide(db: Session, tenant_id: str, request_id: uuid.UUID, decided_by: uuid.UUID, approve: bool) -> bool:
    return db.execute(
        text("UPDATE approval_requests SET status = :s, decided_by = :d, decided_at = now() "
             "WHERE tenant_id = :t AND id = :id AND status = 'PENDING' AND expires_at > now()"),
        {"s": "APPROVED" if approve else "REJECTED", "d": decided_by, "t": tenant_id, "id": request_id},
    ).rowcount == 1
