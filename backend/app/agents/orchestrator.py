"""Agent orchestrator. The BRAIN decides which tools to use; discovery and execution go through the embedded MCP
client/server; the executor authorises every call. The orchestrator itself makes NO authorisation decisions."""
import logging
from dataclasses import dataclass, field

from app.agents.brain import AgentBrain, PlannedCall, StepOutcome
from app.agents.factory import build_brains
from app.agents.results import ToolResult
from app.agents.tool_executor import ToolExecutor
from app.audit.service import AuditEvent, AuditService
from app.core.config import get_settings
from app.core.security import RequestContext
from app.guardrails import Guardrails
from app.mcp.client import InProcessTransport, McpClient
from app.mcp.server import McpServer

log = logging.getLogger("orchestrator")

MAX_STEPS = 3   # an LLM can't make the backend loop or fan out without bound


@dataclass
class ChatOutcome:
    reply: str
    steps: list[ToolResult] = field(default_factory=list)
    planned: list[PlannedCall] = field(default_factory=list)
    guardrails: list[str] = field(default_factory=list)
    transport: str = "mcp"


class AgentOrchestrator:
    def __init__(self, executor: ToolExecutor, audit: AuditService, brains: dict[str, AgentBrain] | None = None,
                 guardrails: Guardrails | None = None):
        self._executor = executor
        self._audit = audit
        settings = get_settings()
        self._brains: dict[str, AgentBrain] = brains or build_brains(settings)
        self.guardrails = guardrails or Guardrails(settings.guardrail_mode)

    def has_brain(self, agent_id: str) -> bool:
        return agent_id in self._brains

    def run(self, ctx: RequestContext, agent_id: str, message: str, input_flags: list[str] | None = None) -> ChatOutcome:
        brain = self._brains[agent_id]
        mcp = McpClient(InProcessTransport(McpServer(self._executor, ctx, agent_id)))
        mcp.initialize()
        catalogue = mcp.list_tools()          # MCP tool discovery; the brain sees names/schemas, never identity
        ctx.db.rollback()

        planned = brain.plan(message, catalogue)[:MAX_STEPS]
        results: list[ToolResult] = []
        outcomes: list[StepOutcome] = []
        for call in planned:
            result = mcp.call_tool(call.tool, call.arguments)       # MCP tools/call -> executor -> OPA
            results.append(result)
            outcomes.append(StepOutcome(call.tool, call.arguments, result.status, result.message, result.data,
                                        result.reasons, result.approval_request_id))
        reply = brain.respond(message, outcomes)
        reply, redactions = self.guardrails.redact(reply)

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
            detail={"steps": len(planned), "tools": ",".join(c.tool for c in planned)[:150], "transport": "mcp",
                    "guardrail_flags": ",".join(sorted(set(flags)))[:150]}))
        return ChatOutcome(reply=reply, steps=results, planned=planned, guardrails=sorted(set(flags)))
