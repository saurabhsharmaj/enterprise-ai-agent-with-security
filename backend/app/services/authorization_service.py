"""Authorisation for non-tool operations (admin screens, listings): ask OPA, audit, raise 403 on deny.
Rules live in Rego; this class contains none of them."""
from fastapi import HTTPException

from app.audit.service import AuditEvent, AuditService
from app.authorization.opa_client import Decision, OpaClient
from app.core.security import RequestContext
from app.tools.messages import explain


class AuthorizationService:
    def __init__(self, opa: OpaClient, audit: AuditService):
        self._opa = opa
        self._audit = audit

    def audit(self, ctx: RequestContext, *, action: str, resource: dict, decision: str, status: str,
              reason: str, agent_id: str | None = None, detail: dict | None = None) -> None:
        p = ctx.principal
        self._audit.record(AuditEvent(
            tenant_id=p.tenant_id, user_id=p.user_id, username=p.username, agent_id=agent_id, action=action,
            resource_type=resource.get("type"), resource_id=str(resource.get("id")) if resource.get("id") else None,
            decision=decision, execution_status=status, reason=reason, correlation_id=ctx.correlation_id,
            channel="api", detail=detail or {}))

    def decide(self, ctx: RequestContext, action: str, resource: dict) -> Decision:
        return self._opa.decide_resource(ctx.principal.opa_subject(), action, resource)

    def require(self, ctx: RequestContext, action: str, resource: dict) -> Decision:
        """Raises 403 unless OPA allows. Both outcomes are audited."""
        decision = self.decide(ctx, action, resource)
        if decision.allow:
            self.audit(ctx, action=action, resource=resource, decision="ALLOW", status="SUCCESS", reason=decision.reason)
            return decision
        self.audit(ctx, action=action, resource=resource, decision="DENY", status="NOT_EXECUTED", reason=decision.reason)
        raise HTTPException(status_code=403, detail={
            "error": "forbidden", "reasons": list(decision.reasons), "message": f"Denied: {explain(decision.reasons)}.",
            "correlation_id": ctx.correlation_id})
