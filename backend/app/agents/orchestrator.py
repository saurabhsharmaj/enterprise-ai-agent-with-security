"""Agent orchestrator: run the brain, push every proposed call through the secure ToolExecutor,
and compose the response. The orchestrator itself makes NO authorisation decisions."""
import logging
from dataclasses import dataclass, field

from app.agents.brain import AgentBrain, PlannedCall, StepOutcome, ToolDescriptor
from app.agents.finance_agent import MockFinanceBrain
from app.agents.tool_executor import ToolExecutor, ToolResult
from app.audit.service import AuditEvent, AuditService
from app.core.security import RequestContext
from app.repositories import agents as agents_repo
from app.tools.registry import REGISTRY

log = logging.getLogger("orchestrator")

MAX_STEPS = 3   # an LLM can't make the backend loop or fan out without bound


@dataclass
class ChatOutcome:
    reply: str
    steps: list[ToolResult] = field(default_factory=list)
    planned: list[PlannedCall] = field(default_factory=list)


class AgentOrchestrator:
    def __init__(self, executor: ToolExecutor, audit: AuditService, brains: dict[str, AgentBrain] | None = None):
        self._executor = executor
        self._audit = audit
        # Swap/extend here to register an LLM-backed brain per agent id.
        self._brains: dict[str, AgentBrain] = brains or {"FINANCE_AGENT": MockFinanceBrain()}

    def has_brain(self, agent_id: str) -> bool:
        return agent_id in self._brains

    def run(self, ctx: RequestContext, agent_id: str, message: str) -> ChatOutcome:
        brain = self._brains[agent_id]
        # The brain sees the tool catalogue (names/schemas) from the DB-configured tools, never the user's identity.
        configured = {t["tool_name"] for t in agents_repo.list_tools(ctx.db, ctx.principal.tenant_id, agent_id)}
        catalogue = [ToolDescriptor(s.name, s.description, s.json_schema()) for s in REGISTRY.values()
                     if s.name in configured]
        ctx.db.rollback()

        planned = brain.plan(message, catalogue)[:MAX_STEPS]
        results: list[ToolResult] = []
        outcomes: list[StepOutcome] = []
        for call in planned:
            result = self._executor.execute(ctx, call.tool, call.arguments, agent_id=agent_id)
            results.append(result)
            outcomes.append(StepOutcome(call.tool, call.arguments, result.status, result.message, result.data,
                                        result.reasons, result.approval_request_id))
        reply = brain.respond(message, outcomes)

        p = ctx.principal
        # Chat-level audit record. The message text itself is NOT stored (may contain sensitive content).
        self._audit.record(AuditEvent(
            tenant_id=p.tenant_id, user_id=p.user_id, username=p.username, agent_id=agent_id, action="chat",
            resource_type="agent", resource_id=agent_id, decision="ALLOW", execution_status="SUCCESS",
            reason="agent_execute_allowed", correlation_id=ctx.correlation_id, channel="agent",
            detail={"steps": len(planned), "tools": ",".join(c.tool for c in planned)[:150]}))
        return ChatOutcome(reply=reply, steps=results, planned=planned)
