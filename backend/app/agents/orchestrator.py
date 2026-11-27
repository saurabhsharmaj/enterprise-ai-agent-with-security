"""Agent orchestrator. A LangChain agent decides which tools to use; discovery and execution go through the embedded
MCP client/server; the executor authorises every call. The orchestrator itself makes NO authorisation decisions."""
import logging
from dataclasses import dataclass, field

from app.agents.brain import PlannedCall
from app.agents.lc_agent import MAX_STEPS, LangChainAgent  # noqa: F401  (MAX_STEPS re-exported for callers/tests)
from app.agents.lc_factory import build_agents
from app.agents.lc_tools import build_tools
from app.agents.results import ToolResult
from app.agents.tool_executor import ToolExecutor
from app.audit.service import AuditEvent, AuditService
from app.core.config import get_settings
from app.core.security import RequestContext
from app.guardrails import Guardrails
from app.mcp.client import InProcessTransport, McpClient
from app.mcp.server import McpServer

log = logging.getLogger("orchestrator")


@dataclass
class ChatOutcome:
    reply: str
    steps: list[ToolResult] = field(default_factory=list)
    planned: list[PlannedCall] = field(default_factory=list)
    guardrails: list[str] = field(default_factory=list)
    transport: str = "mcp"
    engine: str = "langchain"


class AgentOrchestrator:
    def __init__(self, executor: ToolExecutor, audit: AuditService, agents: dict[str, LangChainAgent] | None = None,
                 guardrails: Guardrails | None = None):
        self._executor = executor
        self._audit = audit
        self._agents: dict[str, LangChainAgent] = agents or build_agents()
        self.guardrails = guardrails or Guardrails(get_settings().guardrail_mode)

    def has_agent(self, agent_id: str) -> bool:
        return agent_id in self._agents

    has_brain = has_agent          # backwards-compatible name used by the API layer

    def run(self, ctx: RequestContext, agent_id: str, message: str, input_flags: list[str] | None = None) -> ChatOutcome:
        agent = self._agents[agent_id]
        mcp = McpClient(InProcessTransport(McpServer(self._executor, ctx, agent_id)))
        mcp.initialize()
        catalogue = mcp.list_tools()          # MCP tool discovery; the model sees names/schemas, never identity
        ctx.db.rollback()

        sink: list[ToolResult] = []
        tools = build_tools(mcp, catalogue, sink)                  # LangChain tools -> MCP -> executor -> OPA
        run = agent.run(message, mcp, tools, sink)
        reply, redactions = self.guardrails.redact(run.reply)
        results = run.results

        flags = list(input_flags or []) + redactions
        for r in results:
            if r.tool == "ask_documents" and (r.data or {}).get("flagged_passages"):
                flags.append("injection_in_retrieved_document")

        p = ctx.principal
        # Chat-level audit record. The message text itself is NOT stored (may contain sensitive content).
        self._audit.record(AuditEvent(
            tenant_id=p.tenant_id, user_id=p.user_id, username=p.username, agent_id=agent_id, action="chat",
            resource_type="agent", resource_id=agent_id, decision="ALLOW", execution_status="SUCCESS",
            reason="agent_execute_allowed", correlation_id=ctx.correlation_id, channel="agent",
            detail={"steps": len(run.planned), "tools": ",".join(c.tool for c in run.planned)[:150],
                    "transport": "mcp", "engine": "langchain",
                    "guardrail_flags": ",".join(sorted(set(flags)))[:150]}))
        return ChatOutcome(reply=reply, steps=results, planned=run.planned, guardrails=sorted(set(flags)))
