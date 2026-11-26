"""MCP server (JSON-RPC 2.0, Streamable-HTTP style request/response, protocol 2025-06-18).

Identity is NEVER part of the MCP payload: the server is built for one authenticated RequestContext, taken from the
validated bearer token. A client (or LLM) cannot name a user/tenant/role in tools/call; if it adds such fields they
are ignored (arguments are validated strictly by the executor and unknown fields are rejected).
"""
from dataclasses import asdict
from typing import Any

from app.agents.results import ToolResult
from app.agents.tool_executor import ToolExecutor
from app.core.security import RequestContext
from app.repositories import agents as agents_repo
from app.tools.registry import REGISTRY

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_VERSIONS = {"2025-06-18", "2025-03-26"}
SERVER_INFO = {"name": "enterprise-ai-mcp", "version": "1.0.0"}

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603

_READ_ACTIONS = {"read", "search", "list"}


def _err(rid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _ok(rid: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


class McpServer:
    def __init__(self, executor: ToolExecutor, ctx: RequestContext, agent_id: str):
        self._executor = executor
        self._ctx = ctx
        self._agent_id = agent_id

    # ------------------------------------------------------------------------------------------
    def handle(self, msg: Any) -> dict | None:
        """Returns the JSON-RPC response, or None for notifications (no id)."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return _err(msg.get("id") if isinstance(msg, dict) else None, INVALID_REQUEST, "Invalid Request")
        method, rid, params = msg["method"], msg.get("id"), msg.get("params") or {}
        is_notification = "id" not in msg
        if not isinstance(params, dict):
            return None if is_notification else _err(rid, INVALID_PARAMS, "params must be an object")
        if is_notification:
            return None                                   # e.g. notifications/initialized
        try:
            if method == "initialize":
                return _ok(rid, self._initialize(params))
            if method == "ping":
                return _ok(rid, {})
            if method == "tools/list":
                return _ok(rid, {"tools": self._list_tools()})
            if method == "tools/call":
                return self._call_tool(rid, params)
            return _err(rid, METHOD_NOT_FOUND, f"Method not found: {method[:64]}")
        except Exception:                                  # never leak internals through the protocol
            return _err(rid, INTERNAL_ERROR, "Internal error")

    # ------------------------------------------------------------------------------------------
    def _initialize(self, params: dict) -> dict:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        return {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": "Tools are authorised per call by the platform; denied calls return isError=true."}

    def _list_tools(self) -> list[dict]:
        p = self._ctx.principal
        configured = {t["tool_name"]: t for t in agents_repo.list_tools(self._ctx.db, p.tenant_id, self._agent_id)}
        self._ctx.db.rollback()
        tools = []
        for spec in REGISTRY.values():
            cfg = configured.get(spec.name)
            if cfg is None or cfg.get("enabled") is False:
                continue
            read_only = spec.action in _READ_ACTIONS
            tools.append({
                "name": spec.name, "title": spec.name.replace("_", " ").title(), "description": spec.description,
                "inputSchema": spec.json_schema(),
                "annotations": {"readOnlyHint": read_only, "destructiveHint": not read_only, "idempotentHint": read_only,
                                "openWorldHint": False},
            })
        return tools

    def _call_tool(self, rid: Any, params: dict) -> dict:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name or len(name) > 64:
            return _err(rid, INVALID_PARAMS, "name is required")
        if not isinstance(arguments, dict):
            return _err(rid, INVALID_PARAMS, "arguments must be an object")
        # The ONLY execution path: the secure executor (validate -> OPA -> approval gate -> execute -> audit).
        result = self._executor.execute(self._ctx, name, arguments, agent_id=self._agent_id)
        failed = result.status not in ("success", "pending_approval")
        return _ok(rid, {"content": [{"type": "text", "text": result.message or result.status}],
                         "structuredContent": _to_structured(result), "isError": failed})


def _to_structured(r: ToolResult) -> dict:
    return asdict(r)
