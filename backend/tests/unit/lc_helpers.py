"""Shared test doubles for the LangChain agent tests."""
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.outputs import ChatGeneration, ChatResult


class ScriptedModel(BaseChatModel):
    """Plays back a list of AIMessages (or raises) and records what it was sent."""
    script: list[Any] = []
    seen: list[Any] = []
    bound: list[str] = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools, **kwargs):
        return self.model_copy(update={"bound": [t.name for t in tools]})

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.seen.append(list(messages))
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return ChatResult(generations=[ChatGeneration(message=step)])


def call(name, args, cid):
    return {"name": name, "args": args, "id": cid, "type": "tool_call"}
