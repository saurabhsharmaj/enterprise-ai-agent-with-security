"""LangChain tools backed by the embedded MCP client.

Every LangChain tool is a thin shell around `McpClient.call_tool`, which goes to the MCP server and from there to the
ToolExecutor (strict args -> DB-loaded resource -> OPA -> human-approval gate -> execute -> audit). LangChain therefore
adds orchestration, NOT privilege: there is no code path from a LangChain tool to a repository, the database or a
token that does not pass through the executor.

The tool's `args_schema` is the JSON schema advertised by MCP. It is only a hint for the model; LangChain does not
validate against it here (a dict schema is passed through) and the executor re-validates strictly (unknown fields rejected).
"""
import json
from typing import Any

from langchain_core.tools import StructuredTool

from app.agents.brain import ToolDescriptor
from app.agents.results import ToolResult
from app.mcp.client import McpClient

MAX_TOOL_OUTPUT_CHARS = 6000
WITHHELD = "[passage withheld: it contains instruction-like text]"


def render_for_model(r: ToolResult) -> str:
    """What the MODEL sees of a tool result. Everything inside is untrusted data, never instructions."""
    payload: dict[str, Any] = {"status": r.status, "message": r.message}
    if r.reasons:
        payload["reasons"] = r.reasons
    if r.status == "success" and r.data is not None:
        data = dict(r.data)
        if isinstance(data.get("passages"), list):          # RAG: never hand flagged passages to the model
            data["passages"] = [
                {**p, "text": WITHHELD} if isinstance(p, dict) and p.get("suspicious") else p for p in data["passages"]]
        payload["data"] = data
    body = json.dumps(payload, default=str)[:MAX_TOOL_OUTPUT_CHARS]
    return f'<tool_result untrusted="true">{body}</tool_result>'


def make_tool(mcp: McpClient, name: str, description: str, schema: dict, sink: list[ToolResult]) -> StructuredTool:
    def _run(**kwargs: Any) -> tuple[str, ToolResult]:
        result = mcp.call_tool(name, kwargs)                 # MCP tools/call -> ToolExecutor -> OPA
        sink.append(result)
        return render_for_model(result), result

    return StructuredTool(name=name, description=description or name, args_schema=schema or {"type": "object"},
                          func=_run, response_format="content_and_artifact")


def build_tools(mcp: McpClient, catalogue: list[ToolDescriptor], sink: list[ToolResult]) -> list[StructuredTool]:
    return [make_tool(mcp, t.name, t.description, t.schema, sink) for t in catalogue]
