from decimal import Decimal
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChatRequest(_Strict):
    # The ONLY thing the client sends. No user id, tenant, roles or limits: those come from the token + DB.
    message: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class AuthzCheckRequest(_Strict):
    action: Literal["read", "search", "approve", "create", "manage", "execute", "configure", "decide"]
    resource_type: Literal["invoice", "document", "purchase_order", "user", "role", "permission", "audit",
                           "agent", "approval_request"]
    resource_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_\-]{1,64}$")] | None = None


class UserUpdate(_Strict):
    is_active: bool | None = None
    approval_limit: Decimal | None = Field(default=None, ge=0, le=Decimal("100000000"), decimal_places=2)


class AgentUpdate(_Strict):
    enabled: bool


class ToolUpdate(_Strict):
    enabled: bool | None = None
    requires_approval: bool | None = None


class ApprovalDecision(_Strict):
    decision: Literal["APPROVE", "REJECT"]
