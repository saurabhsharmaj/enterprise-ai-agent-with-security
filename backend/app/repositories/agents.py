from sqlalchemy import text
from sqlalchemy.orm import Session


def list_agents(db: Session, tenant_id: str) -> list[dict]:
    return [dict(r) for r in db.execute(
        text("SELECT id, tenant_id, name, description, enabled FROM agents WHERE tenant_id = :t ORDER BY id"),
        {"t": tenant_id}).mappings().all()]


def get_agent(db: Session, tenant_id: str, agent_id: str) -> dict | None:
    row = db.execute(
        text("SELECT id, tenant_id, name, description, enabled FROM agents WHERE tenant_id = :t AND id = :id"),
        {"t": tenant_id, "id": agent_id}).mappings().first()
    return dict(row) if row else None


def list_tools(db: Session, tenant_id: str, agent_id: str) -> list[dict]:
    return [dict(r) for r in db.execute(
        text("SELECT tool_name, description, enabled, requires_approval FROM agent_tools "
             "WHERE tenant_id = :t AND agent_id = :a ORDER BY tool_name"),
        {"t": tenant_id, "a": agent_id}).mappings().all()]


def get_tool(db: Session, tenant_id: str, agent_id: str, tool_name: str) -> dict | None:
    row = db.execute(
        text("SELECT tool_name, enabled, requires_approval FROM agent_tools "
             "WHERE tenant_id = :t AND agent_id = :a AND tool_name = :n"),
        {"t": tenant_id, "a": agent_id, "n": tool_name}).mappings().first()
    return dict(row) if row else None


def tool_requires_approval_anywhere(db: Session, tenant_id: str, tool_name: str) -> bool:
    """REST calls have no agent; if ANY agent of the tenant gates this tool, REST is gated too, so the
    approval switch cannot be bypassed by calling the API directly."""
    return bool(db.execute(
        text("SELECT COALESCE(bool_or(requires_approval), false) FROM agent_tools "
             "WHERE tenant_id = :t AND tool_name = :n"), {"t": tenant_id, "n": tool_name}).scalar())


def set_enabled(db: Session, tenant_id: str, agent_id: str, enabled: bool) -> bool:
    return db.execute(text("UPDATE agents SET enabled = :e WHERE tenant_id = :t AND id = :id"),
                      {"e": enabled, "t": tenant_id, "id": agent_id}).rowcount == 1


def update_tool(db: Session, tenant_id: str, agent_id: str, tool_name: str, enabled: bool | None,
                requires_approval: bool | None) -> bool:
    return db.execute(
        text("UPDATE agent_tools SET enabled = COALESCE(:e, enabled), "
             "requires_approval = COALESCE(:r, requires_approval) "
             "WHERE tenant_id = :t AND agent_id = :a AND tool_name = :n"),
        {"e": enabled, "r": requires_approval, "t": tenant_id, "a": agent_id, "n": tool_name}).rowcount == 1
