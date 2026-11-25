from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_authz
from app.audit.service import AuditService, get_audit
from app.authorization.opa_client import OpaClient, get_opa
from app.core.security import RequestContext, get_request_context, rate_limit
from app.repositories import admin as repo
from app.repositories import agents as agents_repo
from app.repositories import approvals as approvals_repo
from app.repositories import invoices as invoices_repo
from app.schemas.api import ApprovalDecision, AuthzCheckRequest, UserUpdate
from app.services.authorization_service import AuthorizationService
from app.tools.invoice_tools import invoice_resource
from app.tools.messages import explain

router = APIRouter()


def _collection(ctx: RequestContext, rtype: str) -> dict:
    return {"type": rtype, "id": "*", "tenant_id": ctx.principal.tenant_id, "scope": "collection"}


# ------------------------------------------------------------------------------------------ users
@router.get("/users", tags=["admin"], summary="Users of your tenant (admin)")
def list_users(ctx: RequestContext = Depends(get_request_context),
               authz: AuthorizationService = Depends(get_authz)) -> dict:
    authz.require(ctx, "read", _collection(ctx, "user"))
    return {"users": repo.list_users(ctx.db, ctx.principal.tenant_id)}


@router.patch("/users/{user_id}", tags=["admin"], summary="Activate/deactivate a user or change an approval limit (admin)",
              dependencies=[Depends(rate_limit("sensitive", "rate_limit_sensitive_per_minute"))])
def update_user(user_id: UUID, body: UserUpdate, ctx: RequestContext = Depends(get_request_context),
                authz: AuthorizationService = Depends(get_authz)) -> dict:
    p = ctx.principal
    if body.is_active is None and body.approval_limit is None:
        raise HTTPException(422, detail={"error": "nothing_to_update"})
    target = repo.get_user(ctx.db, p.tenant_id, user_id)
    if target is None:
        raise HTTPException(404, detail={"error": "not_found"})
    authz.require(ctx, "manage", {"type": "user", "id": str(user_id), "tenant_id": target["tenant_id"]})
    if user_id == p.user_id and body.is_active is False:
        raise HTTPException(400, detail={"error": "cannot_deactivate_self"})
    repo.update_user(ctx.db, p.tenant_id, user_id, body.is_active, body.approval_limit)
    ctx.db.commit()
    return {"id": str(user_id), "updated": True}


# ---------------------------------------------------------------------------------- roles / perms
@router.get("/roles", tags=["admin"], summary="Roles and their permissions (admin). Roles are managed in Keycloak + policy data.")
def list_roles(ctx: RequestContext = Depends(get_request_context),
               authz: AuthorizationService = Depends(get_authz)) -> dict:
    authz.require(ctx, "read", _collection(ctx, "role"))
    return {"roles": repo.list_roles(ctx.db)}


@router.get("/permissions", tags=["admin"], summary="All permissions (admin)")
def list_permissions(ctx: RequestContext = Depends(get_request_context),
                     authz: AuthorizationService = Depends(get_authz)) -> dict:
    authz.require(ctx, "read", _collection(ctx, "permission"))
    return {"permissions": repo.list_permissions(ctx.db)}


# ------------------------------------------------------------------------------------ audit logs
@router.get("/audit-logs", tags=["admin"], summary="Audit trail of your tenant (admin)")
def audit_logs(limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0, le=100000),
               decision: str | None = Query(default=None, pattern=r"^(ALLOW|DENY|PENDING)$"),
               user_id: UUID | None = None,
               correlation_id: str | None = Query(default=None, pattern=r"^[A-Za-z0-9\-]{8,64}$"),
               ctx: RequestContext = Depends(get_request_context),
               authz: AuthorizationService = Depends(get_authz)) -> dict:
    authz.require(ctx, "read", _collection(ctx, "audit"))
    rows = repo.list_audit(ctx.db, ctx.principal.tenant_id, limit=limit, offset=offset, decision=decision,
                           user_id=user_id, correlation_id=correlation_id)
    return {"audit_logs": rows, "limit": limit, "offset": offset}


# ----------------------------------------------------------------------------------- approvals
@router.get("/approvals", tags=["approvals"], summary="Human-approval requests (admins: all in tenant; others: your own)")
def list_approvals(ctx: RequestContext = Depends(get_request_context),
                   authz: AuthorizationService = Depends(get_authz)) -> dict:
    authz.require(ctx, "read", _collection(ctx, "approval_request"))
    p = ctx.principal
    # Row scope is driven by policy DATA (who holds approval_request:decide), not by a role-name check.
    can_review = "approval_request:decide" in repo.permissions_for_roles(ctx.db, list(p.roles))
    rows = approvals_repo.list_requests(ctx.db, p.tenant_id, None if can_review else p.user_id)
    return {"approvals": rows}


@router.post("/approvals/{request_id}/decision", tags=["approvals"], summary="Approve or reject a pending request (admin)",
             dependencies=[Depends(rate_limit("sensitive", "rate_limit_sensitive_per_minute"))])
def decide_approval(request_id: UUID, body: ApprovalDecision, ctx: RequestContext = Depends(get_request_context),
                    authz: AuthorizationService = Depends(get_authz)) -> dict:
    p = ctx.principal
    req = approvals_repo.get(ctx.db, p.tenant_id, request_id)
    if req is None:
        raise HTTPException(404, detail={"error": "not_found"})
    authz.require(ctx, "decide", {"type": "approval_request", "id": str(request_id), "tenant_id": req["tenant_id"],
                                  "requester_id": str(req["requester_id"]), "status": req["status"]})
    if not approvals_repo.decide(ctx.db, p.tenant_id, request_id, p.user_id, body.decision == "APPROVE"):
        ctx.db.rollback()
        raise HTTPException(409, detail={"error": "request_not_pending_or_expired"})
    ctx.db.commit()
    return {"id": str(request_id), "status": "APPROVED" if body.decision == "APPROVE" else "REJECTED"}


# -------------------------------------------------------------------- authorization dry-run
@router.post("/authorization/check", tags=["authorization"],
             summary="Dry-run: would OPA allow ME to do this? (server builds the OPA input; you never supply attributes)",
             dependencies=[Depends(rate_limit("sensitive", "rate_limit_sensitive_per_minute"))])
def authorization_check(body: AuthzCheckRequest, ctx: RequestContext = Depends(get_request_context),
                        authz: AuthorizationService = Depends(get_authz),
                        opa: OpaClient = Depends(get_opa), audit: AuditService = Depends(get_audit)) -> dict:
    """Not a generic OPA proxy: the caller can only ask about THEMSELVES, and resource attributes are
    loaded from the database. The subject always comes from the validated token."""
    p = ctx.principal
    if body.resource_id and body.resource_type != "invoice":
        raise HTTPException(422, detail={"error": "resource_id_supported_for_invoice_only"})
    if body.resource_type == "invoice" and body.resource_id:
        row = invoices_repo.get(ctx.db, p.tenant_id, body.resource_id)
        if row is None:
            return {"allowed": False, "reasons": ["resource_not_found"], "explanation": explain(["resource_not_found"]),
                    "correlation_id": ctx.correlation_id}
        resource = invoice_resource(row)
    else:
        resource = _collection(ctx, body.resource_type)
    if body.resource_type == "agent" and body.action == "execute":
        raise HTTPException(422, detail={"error": "use_agents_endpoint_for_execute"})
    decision = authz.decide(ctx, body.action, resource)
    authz.audit(ctx, action="check", resource=resource, decision="ALLOW" if decision.allow else "DENY",
                status="NOT_EXECUTED", reason=decision.reason, detail={"checked_action": body.action})
    return {"allowed": decision.allow, "reasons": list(decision.reasons), "explanation": explain(decision.reasons),
            "correlation_id": ctx.correlation_id}
