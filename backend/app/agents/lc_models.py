"""Chat models used by the LangChain agent.

* `llm`  (AGENT_BRAIN=llm + ANTHROPIC_API_KEY): `langchain_anthropic.ChatAnthropic`.
* `mock` (default): `DeterministicFinanceModel`, a LangChain `BaseChatModel` that needs no API key and no network. It
  emits tool calls from fixed rules (the demo/test model) and then writes the reply from the tool results, so the whole
  LangChain loop (tool calling, ToolMessages, step cap) is exercised identically in both modes.
"""
import logging
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from app.agents.brain import StepOutcome, ToolDescriptor
from app.agents.finance_agent import MockFinanceBrain
from app.agents.results import ToolResult
from app.core.config import Settings

log = logging.getLogger("lc_models")


class DeterministicFinanceModel(BaseChatModel):
    tool_names: list[str] = []

    @property
    def _llm_type(self) -> str:
        return "deterministic-finance-rules"

    def bind_tools(self, tools: Any, *, tool_choice: Any = None, **kwargs: Any) -> "DeterministicFinanceModel":
        names = [t["name"] if isinstance(t, dict) else getattr(t, "name", str(t)) for t in tools]
        return self.model_copy(update={"tool_names": names})

    def _generate(self, messages: list[BaseMessage], stop: list[str] | None = None, run_manager: Any = None,
                  **kwargs: Any) -> ChatResult:
        rules = MockFinanceBrain()
        human = next((m.content for m in reversed(messages) if isinstance(m, HumanMessage)), "")
        human = human if isinstance(human, str) else str(human)
        tool_msgs = [m for m in messages if isinstance(m, ToolMessage)]
        if not tool_msgs:
            catalogue = [ToolDescriptor(n, "", {}) for n in self.tool_names]
            calls = rules.plan(human, catalogue)
            if calls:
                ai = AIMessage(content="", tool_calls=[
                    {"name": c.tool, "args": c.arguments, "id": f"call_{i}", "type": "tool_call"}
                    for i, c in enumerate(calls)])
            else:
                ai = AIMessage(content=rules.respond(human, []))
        else:
            args_by_id = {tc["id"]: tc["args"] for m in messages if isinstance(m, AIMessage) for tc in m.tool_calls}
            outcomes = []
            for m in tool_msgs:
                r = m.artifact if isinstance(m.artifact, ToolResult) else None
                if r is None:
                    continue
                outcomes.append(StepOutcome(r.tool, args_by_id.get(m.tool_call_id, {}), r.status, r.message, r.data,
                                            r.reasons, r.approval_request_id))
            ai = AIMessage(content=rules.respond(human, outcomes))
        return ChatResult(generations=[ChatGeneration(message=ai)])


def build_chat_model(settings: Settings) -> BaseChatModel:
    if settings.agent_brain.lower() == "llm":
        if settings.anthropic_api_key:
            from langchain_anthropic import ChatAnthropic
            kwargs: dict[str, Any] = {"model": settings.llm_model, "api_key": settings.anthropic_api_key,
                                      "timeout": settings.llm_timeout_seconds, "max_retries": 1, "max_tokens": 1024,
                                      "temperature": 0}
            if settings.anthropic_base_url and "api.anthropic.com" not in settings.anthropic_base_url:
                kwargs["base_url"] = settings.anthropic_base_url
            return ChatAnthropic(**kwargs)
        log.warning("AGENT_BRAIN=llm but ANTHROPIC_API_KEY is empty: using the deterministic model")
    return DeterministicFinanceModel()
