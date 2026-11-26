"""Embedded Model Context Protocol (MCP) server + client.

Server: exposes an agent's tools (tools/list, tools/call) over JSON-RPC 2.0. Every tools/call is executed by the
SAME ToolExecutor as REST calls, so MCP gives a standard interface but NO new privilege.
Client: used by the orchestrator, which discovers tools through MCP and executes the brain's choices through MCP.
"""
