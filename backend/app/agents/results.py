"""Result type shared by the executor, the MCP layer and the orchestrator (kept separate to avoid import cycles)."""
from dataclasses import dataclass, field


@dataclass
class ToolResult:
    tool: str
    status: str            # success | denied | pending_approval | invalid_arguments | not_found | error
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    message: str = ""
    data: dict | None = None
    approval_request_id: str | None = None
    audit_id: str | None = None
