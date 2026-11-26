"""Embedded MCP server/client: protocol behaviour, and proof that tools/call cannot bypass the executor."""
import json
from types import SimpleNamespace

import pytest

from app.agents.results import ToolResult
from app.mcp import server as srv
from app.mcp.client import HttpTransport, InProcessTransport, McpClient
from app.mcp.server import McpServer


class FakeDb:
    def rollback(self):
        pass


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def execute(self, ctx, tool, args, *, agent_id=None):
        self.calls.append((tool, args, agent_id))
        if tool == "approve_invoice":
            return ToolResult(tool, "denied", False, ["approval_limit_exceeded"], "Denied: limit.", audit_id="a1")
        if tool == "nope":
            return ToolResult(tool, "denied", False, ["unknown_tool"], "Denied: unknown tool.")
        if tool == "gate":
            return ToolResult(tool, "pending_approval", True, ["human_approval_required"], "waiting",
                              approval_request_id="r1")
        return ToolResult(tool, "success", True, ["allowed_by_policy"], "OK", data={"count": 1}, audit_id="a2")


@pytest.fixture()
def rig(monkeypatch):
    tools = [{"tool_name": n, "enabled": True, "requires_approval": False, "description": ""}
             for n in ("search_invoices", "approve_invoice", "ask_documents")] + \
            [{"tool_name": "read_invoice", "enabled": False, "requires_approval": False, "description": ""}]
    monkeypatch.setattr(srv.agents_repo, "list_tools", lambda db, t, a: tools)
    ex = FakeExecutor()
    ctx = SimpleNamespace(principal=SimpleNamespace(tenant_id="TENANT_A"), db=FakeDb())
    server = McpServer(ex, ctx, "FINANCE_AGENT")
    return ex, server, McpClient(InProcessTransport(server))


def test_initialize_and_discovery(rig):
    ex, server, client = rig
    info = client.initialize()
    assert info["protocolVersion"] == srv.PROTOCOL_VERSION and client.server_info["name"] == "enterprise-ai-mcp"
    names = {t.name for t in client.list_tools()}
    assert names == {"search_invoices", "approve_invoice", "ask_documents"}       # disabled tool is not offered
    tools = {t["name"]: t for t in server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
    assert tools["search_invoices"]["annotations"]["readOnlyHint"] is True
    assert tools["approve_invoice"]["annotations"]["destructiveHint"] is True
    assert tools["ask_documents"]["inputSchema"]["properties"]["question"]


def test_call_goes_through_the_executor_with_the_agent_id(rig):
    ex, _, client = rig
    r = client.call_tool("search_invoices", {"status": "PENDING"})
    assert r.status == "success" and r.data == {"count": 1} and r.audit_id == "a2"
    assert ex.calls == [("search_invoices", {"status": "PENDING"}, "FINANCE_AGENT")]


def test_denial_is_reported_as_is_error_and_preserved(rig):
    _, server, client = rig
    raw = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "approve_invoice", "arguments": {"invoice_id": "INV-1"}}})
    assert raw["result"]["isError"] is True
    r = client.call_tool("approve_invoice", {"invoice_id": "INV-1"})
    assert (r.status, r.allowed, r.reasons) == ("denied", False, ["approval_limit_exceeded"])


def test_pending_approval_is_not_an_error(rig):
    _, server, client = rig
    raw = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "gate", "arguments": {}}})
    assert raw["result"]["isError"] is False
    assert client.call_tool("gate", {}).approval_request_id == "r1"


def test_unlisted_tool_still_reaches_executor_which_denies(rig):
    ex, _, client = rig
    r = client.call_tool("nope", {})
    assert r.status == "denied" and ex.calls[-1][0] == "nope"      # the server never authorises by itself


def test_identity_fields_in_arguments_are_just_arguments(rig):
    ex, _, client = rig
    client.call_tool("search_invoices", {"tenant_id": "TENANT_B", "user_id": "x", "roles": ["ADMIN"]})
    assert ex.calls[-1][1] == {"tenant_id": "TENANT_B", "user_id": "x", "roles": ["ADMIN"]}  # executor rejects (extra=forbid)


@pytest.mark.parametrize("msg,code", [
    ("not a dict", srv.INVALID_REQUEST),
    ({"jsonrpc": "1.0", "id": 1, "method": "ping"}, srv.INVALID_REQUEST),
    ({"jsonrpc": "2.0", "id": 1}, srv.INVALID_REQUEST),
    ({"jsonrpc": "2.0", "id": 1, "method": "resources/list"}, srv.METHOD_NOT_FOUND),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {}}}, srv.INVALID_PARAMS),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x", "arguments": [1]}}, srv.INVALID_PARAMS),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "x"}, srv.INVALID_PARAMS),
])
def test_protocol_errors(rig, msg, code):
    _, server, _ = rig
    assert server.handle(msg)["error"]["code"] == code


def test_notifications_get_no_response_and_ping_works(rig):
    _, server, _ = rig
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.handle({"jsonrpc": "2.0", "id": 9, "method": "ping"})["result"] == {}


def test_executor_crash_does_not_leak_internals(rig):
    ex, server, _ = rig
    ex.execute = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("password=hunter2 in stack"))
    out = server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "x", "arguments": {}}})
    assert out["error"]["message"] == "Internal error" and "hunter2" not in json.dumps(out)


def test_http_transport_speaks_the_same_protocol(rig):
    import httpx
    _, server, _ = rig
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"], seen["ver"] = request.headers["authorization"], request.headers["mcp-protocol-version"]
        reply = server.handle(json.loads(request.content))
        return httpx.Response(202) if reply is None else httpx.Response(200, json=reply)

    client = McpClient(HttpTransport("http://mcp.test/mcp/FINANCE_AGENT", "user-token",
                                     httpx.Client(transport=httpx.MockTransport(handler))))
    client.initialize()
    assert {t.name for t in client.list_tools()} >= {"search_invoices"}
    assert seen["auth"] == "Bearer user-token" and seen["ver"] == srv.PROTOCOL_VERSION
