"""MCP client used by the orchestrator. Transports: in-process (default; no network hop) or HTTP (any MCP server)."""
import itertools
from typing import Any, Protocol

import httpx

from app.agents.brain import ToolDescriptor
from app.agents.results import ToolResult
from app.mcp.server import PROTOCOL_VERSION, McpServer


class McpError(Exception):
    pass


class Transport(Protocol):
    def send(self, message: dict) -> dict | None: ...


class InProcessTransport:
    def __init__(self, server: McpServer):
        self._server = server

    def send(self, message: dict) -> dict | None:
        return self._server.handle(message)


class HttpTransport:
    """Talks to a remote MCP server (Streamable HTTP, JSON responses). The bearer token is the USER's token."""

    def __init__(self, url: str, token: str, client: httpx.Client | None = None, timeout: float = 15.0):
        self._url, self._token = url, token
        self._http = client or httpx.Client(timeout=timeout)

    def send(self, message: dict) -> dict | None:
        r = self._http.post(self._url, json=message, headers={
            "Authorization": f"Bearer {self._token}", "Accept": "application/json",
            "MCP-Protocol-Version": PROTOCOL_VERSION})
        if r.status_code == 202:
            return None
        r.raise_for_status()
        return r.json()


class McpClient:
    def __init__(self, transport: Transport):
        self._t = transport
        self._ids = itertools.count(1)
        self.server_info: dict = {}

    def _request(self, method: str, params: dict | None = None) -> dict:
        resp = self._t.send({"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}})
        if not isinstance(resp, dict):
            raise McpError("no response")
        if "error" in resp:
            raise McpError(str(resp["error"].get("message", "error"))[:200])
        return resp.get("result") or {}

    def initialize(self) -> dict:
        res = self._request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                           "clientInfo": {"name": "enterprise-ai-orchestrator", "version": "1.0.0"}})
        self.server_info = res.get("serverInfo", {})
        self._t.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return res

    def list_tools(self) -> list[ToolDescriptor]:
        tools = self._request("tools/list").get("tools", [])
        return [ToolDescriptor(t["name"], t.get("description", ""), t.get("inputSchema", {})) for t in tools]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        try:
            res = self._request("tools/call", {"name": name, "arguments": arguments})
        except McpError as exc:
            return ToolResult(name, "error", False, ["mcp_protocol_error"], f"MCP error: {exc}")
        s = res.get("structuredContent") or {}
        return ToolResult(
            tool=s.get("tool", name), status=s.get("status", "error"), allowed=bool(s.get("allowed", False)),
            reasons=list(s.get("reasons") or []), message=str(s.get("message") or ""), data=s.get("data"),
            approval_request_id=s.get("approval_request_id"), audit_id=s.get("audit_id"))
