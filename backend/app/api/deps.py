from fastapi import Depends
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

from app.agents.orchestrator import AgentOrchestrator
from app.agents.tool_executor import ToolExecutor, ToolResult
from app.audit.service import AuditService, get_audit
from app.authorization.opa_client import OpaClient, get_opa
from app.core.config import Settings, get_settings
from app.services.authorization_service import AuthorizationService


def get_executor(opa: OpaClient = Depends(get_opa), audit: AuditService = Depends(get_audit),
                 settings: Settings = Depends(get_settings)) -> ToolExecutor:
    return ToolExecutor(opa, audit, settings)


def get_orchestrator(executor: ToolExecutor = Depends(get_executor),
                     audit: AuditService = Depends(get_audit)) -> AgentOrchestrator:
    return AgentOrchestrator(executor, audit)


def get_authz(opa: OpaClient = Depends(get_opa), audit: AuditService = Depends(get_audit)) -> AuthorizationService:
    return AuthorizationService(opa, audit)


_HTTP_FOR_STATUS = {"denied": 403, "not_found": 404, "invalid_arguments": 422, "error": 409}


def tool_response(result: ToolResult, correlation_id: str, success_status: int = 200) -> JSONResponse:
    """Maps a ToolResult from the secure executor onto an HTTP response for the REST endpoints."""
    if result.status == "success":
        return JSONResponse(status_code=success_status, content=jsonable_encoder(
            {"correlation_id": correlation_id, "audit_id": result.audit_id, "data": result.data}))
    if result.status == "pending_approval":
        return JSONResponse(status_code=202, content=jsonable_encoder({
            "correlation_id": correlation_id, "audit_id": result.audit_id, "status": "pending_approval",
            "approval_request_id": result.approval_request_id, "message": result.message}))
    raise HTTPException(status_code=_HTTP_FOR_STATUS.get(result.status, 400), detail={
        "error": "forbidden" if result.status == "denied" else result.status, "reasons": result.reasons,
        "message": result.message, "correlation_id": correlation_id})
