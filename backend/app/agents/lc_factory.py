from functools import lru_cache

from langchain_core.language_models.chat_models import BaseChatModel

from app.agents.lc_agent import FINANCE_SYSTEM_PROMPT, LangChainAgent
from app.agents.lc_models import build_chat_model
from app.core.config import get_settings


@lru_cache
def _default_model() -> BaseChatModel:
    return build_chat_model(get_settings())


def build_agents(model: BaseChatModel | None = None) -> dict[str, LangChainAgent]:
    """One LangChain agent per agent id. The chat model is created once and shared (it holds no per-user state)."""
    m = model or _default_model()
    return {"FINANCE_AGENT": LangChainAgent(m, FINANCE_SYSTEM_PROMPT)}
