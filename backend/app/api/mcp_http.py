"""Expose an agent's MCP server over HTTP at POST /mcp/{agent_id} so external MCP clients (IDEs, other agents)
can use the same tools. Same authentication (Keycloak bearer), same agent-level OPA check, same executor."""
from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.agents.tool_executor import ToolExecutor
from app.api.deps import get_executor
from app.audit.service import AuditEvent, AuditService, get_audit
from app.authorization.opa_client import OpaClient, get_opa
from app.core.config import Settings, get_settings
from app.core.security import RequestContext, get_request_context, rate_limit
from app.mcp.server import INVALID_REQUEST, PARSE_ERROR, SUPPORTED_VERSIONS, McpServer, _err
from app.repositories import agents as repo

router = APIRouter(prefix="/mcp", tags=["mcp"])
AgentId = Path(pattern=r"^[A-Z0-9_]{1,64}$")


@router.get("/{agent_id}", include_in_schema=False)
def no_sse(agent_id: str = AgentId) -> Response:
    return Response(status_code=405, headers={"Allow": "POST"})


@router.post("/{agent_id}", summary="MCP (JSON-RPC 2.0) endpoint of an agent",
             dependencies=[Depends(rate_limit("chat", "rate_limit_chat_per_minute"))])
async def mcp_endpoint(request: Request, agent_id: str = AgentId, ctx: RequestContext = Depends(get_request_context),
                       opa: OpaClient = Depends(get_opa), audit: AuditService = Depends(get_audit),
                       executor: ToolExecutor = Depends(get_executor),
                       settings: Settings = Depends(get_settings)) -> Response:
    # DNS-rebinding / CSRF hardening required by the MCP spec: only configured origins may call.
    origin = request.headers.get("origin")
    if origin and origin not in settings.cors_origin_list:
        raise HTTPException(403, detail={"error": "origin_not_allowed"})
    version = request.headers.get("mcp-protocol-version")
    if version and version not in SUPPORTED_VERSIONS:
        raise HTTPException(400, detail={"error": "unsupported_protocol_version"})
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_err(None, PARSE_ERROR, "Parse error"), status_code=400)
    if isinstance(body, list):                                    # batching is not supported
        return JSONResponse(_err(None, INVALID_REQUEST, "Batches are not supported"), status_code=400)

    p = ctx.principal
    agent = repo.get_agent(ctx.db, p.tenant_id, agent_id)
    if agent is None:
        raise HTTPException(404, detail={"error": "not_found"})
    ctx.db.rollback()
    decision = opa.decide_agent(p.opa_subject(), {"id": agent["id"], "enabled": agent["enabled"],
                                                  "tenant_id": agent["tenant_id"]})
    if not decision.allow:
        audit.record(AuditEvent(tenant_id=p.tenant_id, user_id=p.user_id, username=p.username, agent_id=agent_id,
                                action="execute", resource_type="agent", resource_id=agent_id, decision="DENY",
                                execution_status="NOT_EXECUTED", reason=decision.reason,
                                correlation_id=ctx.correlation_id, channel="agent"))
        raise HTTPException(403, detail={"error": "forbidden", "reasons": list(decision.reasons),
                                         "correlation_id": ctx.correlation_id})
    response = McpServer(executor, ctx, agent_id).handle(body)
    if response is None:
        return Response(status_code=202)
    return JSONResponse(jsonable_encoder(response))   # tool data may hold Decimal/UUID/datetime values
