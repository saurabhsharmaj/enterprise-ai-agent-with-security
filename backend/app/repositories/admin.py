"""Users / roles / permissions / audit reads for the administration screens."""
import uuid
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.orm import Session


def list_users(db: Session, tenant_id: str) -> list[dict]:
    rows = db.execute(
        text("SELECT u.id, u.username, u.email, u.full_name, u.department, u.approval_limit, u.is_active, "
             "u.tenant_id, COALESCE(array_agg(r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles "
             "FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id LEFT JOIN roles r ON r.id = ur.role_id "
             "WHERE u.tenant_id = :t GROUP BY u.id ORDER BY u.username"), {"t": tenant_id}).mappings().all()
    return [dict(r) for r in rows]


def get_user(db: Session, tenant_id: str, user_id: uuid.UUID) -> dict | None:
    row = db.execute(text("SELECT id, tenant_id, username, is_active, approval_limit FROM users "
                          "WHERE tenant_id = :t AND id = :id"), {"t": tenant_id, "id": user_id}).mappings().first()
    return dict(row) if row else None


def update_user(db: Session, tenant_id: str, user_id: uuid.UUID, is_active: bool | None,
                approval_limit: Decimal | None) -> bool:
    return db.execute(
        text("UPDATE users SET is_active = COALESCE(:a, is_active), approval_limit = COALESCE(:l, approval_limit) "
             "WHERE tenant_id = :t AND id = :id"),
        {"a": is_active, "l": approval_limit, "t": tenant_id, "id": user_id}).rowcount == 1


def list_roles(db: Session) -> list[dict]:
    rows = db.execute(
        text("SELECT r.id, r.name, r.description, COALESCE(array_agg(p.name ORDER BY p.name) "
             "FILTER (WHERE p.name IS NOT NULL), '{}') AS permissions "
             "FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id "
             "LEFT JOIN permissions p ON p.id = rp.permission_id GROUP BY r.id ORDER BY r.name")).mappings().all()
    return [dict(r) for r in rows]


def list_permissions(db: Session) -> list[dict]:
    return [dict(r) for r in db.execute(
        text("SELECT id, name, description FROM permissions ORDER BY name")).mappings().all()]


def permissions_for_roles(db: Session, roles: list[str]) -> list[str]:
    """UI hints only (what to show/hide). Authorization is always decided by OPA."""
    rows = db.execute(
        text("SELECT DISTINCT p.name FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id "
             "JOIN roles r ON r.id = rp.role_id WHERE r.name = ANY(:roles) ORDER BY p.name"), {"roles": roles})
    return [r[0] for r in rows]


def list_audit(db: Session, tenant_id: str, *, limit: int, offset: int, decision: str | None,
               user_id: uuid.UUID | None, correlation_id: str | None) -> list[dict]:
    sql = ("SELECT audit_id, occurred_at, user_id, username, tenant_id, agent_id, tool_name, resource_type, "
           "resource_id, action, decision, reason, execution_status, correlation_id, channel "
           "FROM audit_logs WHERE tenant_id = :t")
    params: dict = {"t": tenant_id, "limit": limit, "offset": offset}
    if decision:
        sql += " AND decision = :d"
        params["d"] = decision
    if user_id:
        sql += " AND user_id = :u"
        params["u"] = user_id
    if correlation_id:
        sql += " AND correlation_id = :c"
        params["c"] = correlation_id
    sql += " ORDER BY occurred_at DESC, id DESC LIMIT :limit OFFSET :offset"
    return [dict(r) for r in db.execute(text(sql), params).mappings().all()]
