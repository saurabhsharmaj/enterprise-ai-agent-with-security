"""The agent 'brain' abstraction.

A brain turns a user message into PROPOSED tool calls, and turns tool results into a reply. That is
all it can do. It never receives the user's identity, roles, tenant or limits, it has no database or
OPA access, and nothing it returns is treated as authorisation: every proposed call goes through
ToolExecutor, which validates, authorises (OPA) and audits it.

To plug in a real LLM later, implement `AgentBrain` (see README: "Connecting a real LLM").
"""
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolDescriptor:
    """What the brain is told about a tool: name, description, JSON schema. No identity, no rules."""
    name: str
    description: str
    schema: dict


@dataclass
class PlannedCall:
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class StepOutcome:
    """A tool call plus what the secure executor answered (used to compose the reply)."""
    tool: str
    arguments: dict[str, Any]
    status: str
    message: str
    data: dict | None
    reasons: list[str]
    approval_request_id: str | None = None


class AgentBrain(Protocol):
    def plan(self, message: str, tools: list[ToolDescriptor]) -> list[PlannedCall]:
        """Propose tool calls for the message. Output is UNTRUSTED."""

    def respond(self, message: str, outcomes: list[StepOutcome]) -> str:
        """Compose the final reply from executor outcomes."""
