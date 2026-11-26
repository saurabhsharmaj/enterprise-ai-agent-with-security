import logging

from app.agents.brain import AgentBrain
from app.agents.finance_agent import MockFinanceBrain
from app.core.config import Settings

log = logging.getLogger("brain_factory")


def build_brains(settings: Settings) -> dict[str, AgentBrain]:
    if settings.agent_brain.lower() == "llm":
        if settings.anthropic_api_key:
            from app.agents.llm_brain import LlmBrain
            return {"FINANCE_AGENT": LlmBrain(settings.anthropic_api_key, settings.llm_model,
                                              settings.anthropic_base_url, settings.llm_timeout_seconds)}
        log.warning("AGENT_BRAIN=llm but ANTHROPIC_API_KEY is empty: using the deterministic mock brain")
    return {"FINANCE_AGENT": MockFinanceBrain()}
