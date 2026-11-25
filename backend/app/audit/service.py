"""Centralised audit logging.

* Every record is written in its OWN short transaction on its own session, so denied actions and
  failed executions are persisted even though the business transaction rolled back.
* The runtime DB role has INSERT/SELECT only on audit_logs (no UPDATE/DELETE): append-only.
* Secrets never enter the log: only whitelisted scalar fields, an explicit key blocklist, and no
  prompt/message content (the chat endpoint passes only the selected tool names).
"""
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text

from app.core.db import new_tenant_session

log = logging.getLogger("audit")

_SECRET_KEY = re.compile(r"token|password|secret|authorization|credential|api[_-]?key", re.I)
_MAX_DETAIL_BYTES = 2048


@dataclass
class AuditEvent:
    tenant_id: str
    action: str
    decision: str                      # ALLOW | DENY | PENDING
    execution_status: str              # SUCCESS | FAILED | NOT_EXECUTED | PENDING_APPROVAL
    correlation_id: str
    reason: str = ""
    user_id: uuid.UUID | None = None
    username: str | None = None
    agent_id: str | None = None
    tool_name: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    channel: str = "api"
    detail: dict[str, Any] = field(default_factory=dict)


def sanitize_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """Keeps only small scalar values and drops anything that looks like a secret."""
    clean: dict[str, Any] = {}
    for key, value in detail.items():
        if _SECRET_KEY.search(str(key)):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[str(key)] = value[:200] if isinstance(value, str) else value
    while len(json.dumps(clean, default=str)) > _MAX_DETAIL_BYTES and clean:
        clean.popitem()
    return clean


class AuditService:
    def record(self, ev: AuditEvent) -> uuid.UUID | None:
        audit_id = uuid.uuid4()
        session = new_tenant_session(ev.tenant_id)
        try:
            session.execute(
                text(
                    "INSERT INTO audit_logs (audit_id, user_id, username, tenant_id, agent_id, tool_name, "
                    "resource_type, resource_id, action, decision, reason, execution_status, correlation_id, "
                    "channel, detail) VALUES (:audit_id, :user_id, :username, :tenant_id, :agent_id, :tool_name, "
                    ":resource_type, :resource_id, :action, :decision, :reason, :execution_status, "
                    ":correlation_id, :channel, CAST(:detail AS jsonb))"
                ),
                {
                    "audit_id": audit_id, "user_id": ev.user_id, "username": ev.username,
                    "tenant_id": ev.tenant_id, "agent_id": ev.agent_id, "tool_name": ev.tool_name,
                    "resource_type": ev.resource_type, "resource_id": (ev.resource_id or None) and ev.resource_id[:64],
                    "action": ev.action[:32], "decision": ev.decision, "reason": ev.reason[:500],
                    "execution_status": ev.execution_status, "correlation_id": ev.correlation_id,
                    "channel": ev.channel, "detail": json.dumps(sanitize_detail(ev.detail), default=str),
                },
            )
            session.commit()
            return audit_id
        except Exception:
            session.rollback()
            # Never swallow silently, but never include event content (may be sensitive) in the log line.
            log.exception("AUDIT WRITE FAILED action=%s correlation_id=%s", ev.action, ev.correlation_id)
            return None
        finally:
            session.close()


_audit = AuditService()


def get_audit() -> AuditService:
    """Overridable in tests."""
    return _audit
