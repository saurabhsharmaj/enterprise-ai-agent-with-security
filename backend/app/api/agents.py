from fastapi import APIRouter, Depends, HTTPException, Path

from app.agents.orchestrator import AgentOrchestrator
from app.audit.service import AuditEvent, AuditService, get_audit
from app.authorization.opa_client import OpaClient, get_opa
from app.api.deps import get_authz, get_orchestrator
from app.core.security import RequestContext, get_request_context, rate_limit
from app.repositories import agents as repo
from app.schemas.api import AgentUpdate, ChatRequest, ToolUpdate
from app.services.authorization_service import AuthorizationService
from app.tools.messages import explain

router = APIRouter(prefix="/agents", tags=["agents"])
AgentId = Path(pattern=r"^[A-Z0-9_]{1,64}$")
ToolName = Path(pattern=r"^[a-z_]{1,64}$")


def _collection(ctx: RequestContext) -> dict:
    return {"type": "agent", "id": "*", "tenant_id": ctx.principal.tenant_id, "scope": "collection"}


def _agent_view(ctx: RequestContext, opa: OpaClient, agent: dict) -> dict:
    d = opa.decide_agent(ctx.principal.opa_subject(),
                         {"id": agent["id"], "enabled": agent["enabled"], "tenant_id": agent["tenant_id"]})
    return {**agent, "can_execute": d.allow, "execute_denied_reasons": [] if d.allow else list(d.reasons),
            "tools": repo.list_tools(ctx.db, ctx.principal.tenant_id, agent["id"])}


@router.get("", summary="Agents of your tenant, with what you may execute")
def list_agents(ctx: RequestContext = Depends(get_request_context), authz: AuthorizationService = Depends(get_authz),
                opa: OpaClient = Depends(get_opa)) -> dict:
    authz.require(ctx, "read", _collection(ctx))
    return {"agents": [_agent_view(ctx, opa, a) for a in repo.list_agents(ctx.db, ctx.principal.tenant_id)]}


@router.get("/{agent_id}", summary="One agent and its tools")
def get_agent(agent_id: str = AgentId, ctx: RequestContext = Depends(get_request_context),
              authz: AuthorizationService = Depends(get_authz), opa: OpaClient = Depends(get_opa)) -> dict:
    authz.require(ctx, "read", _collection(ctx))
    agent = repo.get_agent(ctx.db, ctx.principal.tenant_id, agent_id)
    if agent is None:
        raise HTTPException(404, detail={"error": "not_found"})
    return _agent_view(ctx, opa, agent)


@router.post("/{agent_id}/chat", summary="Chat with an agent (its tool calls are authorised one by one)",
             dependencies=[Depends(rate_limit("chat", "rate_limit_chat_per_minute"))])
def chat(body: ChatRequest, agent_id: str = AgentId, ctx: RequestContext = Depends(get_request_context),
         opa: OpaClient = Depends(get_opa), audit: AuditService = Depends(get_audit),
         orchestrator: AgentOrchestrator = Depends(get_orchestrator)) -> dict:
    p = ctx.principal
    agent = repo.get_agent(ctx.db, p.tenant_id, agent_id)
    if agent is None:
        raise HTTPException(404, detail={"error": "not_found"})
    ctx.db.rollback()

    # Agent-level authorisation (enabled? tenant? role allow-listed? agent:execute permission?)
    decision = opa.decide_agent(p.opa_subject(), {"id": agent["id"], "enabled": agent["enabled"],
                                                  "tenant_id": agent["tenant_id"]})
    if not decision.allow:
        audit.record(AuditEvent(tenant_id=p.tenant_id, user_id=p.user_id, username=p.username, agent_id=agent_id,
                                action="execute", resource_type="agent", resource_id=agent_id, decision="DENY",
                                execution_status="NOT_EXECUTED", reason=decision.reason,
                                correlation_id=ctx.correlation_id, channel="agent"))
        raise HTTPException(403, detail={"error": "forbidden", "reasons": list(decision.reasons),
                                         "message": f"Denied: {explain(decision.reasons)}.",
                                         "correlation_id": ctx.correlation_id})
    if not orchestrator.has_brain(agent_id):
        raise HTTPException(409, detail={"error": "agent_not_runnable"})

    outcome = orchestrator.run(ctx, agent_id, body.message)
    return {
        "correlation_id": ctx.correlation_id, "agent_id": agent_id, "reply": outcome.reply,
        "steps": [{
            "tool": call.tool, "arguments": call.arguments, "status": r.status, "allowed": r.allowed,
            "reasons": r.reasons, "message": r.message, "data": r.data,
            "approval_request_id": r.approval_request_id, "audit_id": r.audit_id,
        } for call, r in zip(outcome.planned, outcome.steps)],
    }


@router.patch("/{agent_id}", summary="Enable / disable an agent (admin)")
def update_agent(body: AgentUpdate, agent_id: str = AgentId, ctx: RequestContext = Depends(get_request_context),
                 authz: AuthorizationService = Depends(get_authz)) -> dict:
    p = ctx.principal
    agent = repo.get_agent(ctx.db, p.tenant_id, agent_id)
    if agent is None:
        raise HTTPException(404, detail={"error": "not_found"})
    authz.require(ctx, "manage", {"type": "agent", "id": agent_id, "tenant_id": agent["tenant_id"]})
    repo.set_enabled(ctx.db, p.tenant_id, agent_id, body.enabled)
    ctx.db.commit()
    return {"id": agent_id, "enabled": body.enabled}


@router.patch("/{agent_id}/tools/{tool_name}", summary="Configure a tool: enable/disable, human-approval gate (admin)")
def update_tool(body: ToolUpdate, agent_id: str = AgentId, tool_name: str = ToolName,
                ctx: RequestContext = Depends(get_request_context),
                authz: AuthorizationService = Depends(get_authz)) -> dict:
    p = ctx.principal
    if body.enabled is None and body.requires_approval is None:
        raise HTTPException(422, detail={"error": "nothing_to_update"})
    if repo.get_tool(ctx.db, p.tenant_id, agent_id, tool_name) is None:
        raise HTTPException(404, detail={"error": "not_found"})
    authz.require(ctx, "configure", {"type": "tool", "id": f"{agent_id}:{tool_name}", "tenant_id": p.tenant_id})
    repo.update_tool(ctx.db, p.tenant_id, agent_id, tool_name, body.enabled, body.requires_approval)
    ctx.db.commit()
    return {"agent_id": agent_id, **(repo.get_tool(ctx.db, p.tenant_id, agent_id, tool_name) or {})}
