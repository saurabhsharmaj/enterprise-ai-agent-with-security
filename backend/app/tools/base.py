from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.authorization.opa_client import OpaClient
from app.core.security import Principal


class ToolConflict(Exception):
    """The world changed between authorisation and execution (e.g. invoice no longer PENDING)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class ToolContext:
    """Everything a tool may use. Built by the executor from the VALIDATED principal; never from LLM output."""
    principal: Principal
    db: Session
    opa: OpaClient
    correlation_id: str


@dataclass
class Resolved:
    resource: dict        # attributes sent to OPA (input.resource), loaded from the DB, never from the caller
    record: Any = None    # the DB row (full fidelity), passed to execute()


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    resource_type: str
    action: str
    args_model: type[BaseModel]
    resolve: Callable[[ToolContext, Any], Resolved | None]
    execute: Callable[[ToolContext, Any, Resolved], dict]

    def json_schema(self) -> dict:
        return self.args_model.model_json_schema()


def collection_resource(ctx: ToolContext, resource_type: str) -> dict:
    return {"type": resource_type, "id": "*", "tenant_id": ctx.principal.tenant_id, "scope": "collection"}
