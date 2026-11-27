"""Small data types shared by the deterministic rules engine (finance_agent.py) and the MCP layer.

The agent runtime itself is LangChain (see lc_agent.py). Whatever model drives it only PROPOSES tool calls; it never
receives the user's identity, roles, tenant or limits, and nothing it returns is treated as authorisation: every
proposed call goes through MCP -> ToolExecutor, which validates, authorises (OPA) and audits it.
"""
from dataclasses import dataclass, field
from typing import Any


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
    call_id: str | None = None      # provider tool-call id (LLM brains); informational only


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
