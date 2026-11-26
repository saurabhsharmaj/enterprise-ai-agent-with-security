"""The secure tool-execution layer: the ONE choke point through which every tool call passes, whether
it was proposed by the (mock or real) LLM or requested by a REST endpoint.

Order of operations for each call (nothing is skipped, nothing trusts the caller):
  1. tool must exist in the registry                      (unknown tool  -> deny + audit)
  2. arguments validated by a strict schema               (bad/extra args -> reject + audit)
  3. agent + tool configuration loaded from the DB        (not from the prompt)
  4. target resource loaded from the DB, tenant-scoped    (other tenant => "not found": no IDOR)
  5. OPA decision: subject (token+DB) x agent x tool x resource x business rules
  6. deny -> audit + return;  human-approval gate -> park request, audit + return
  7. execute (atomic, guarded SQL)  -> commit
  8. audit the outcome in its own transaction (allowed AND denied AND failed)

The authorisation check (5) runs immediately before execution (7), on data read in (4) in the same
request. The LLM's proposed arguments are only ever *inputs to be validated*, never proof of anything.
"""
import hashlib
import json
import logging
from typing import Any

from pydantic import ValidationError

from app.agents.results import ToolResult  # noqa: F401  (re-exported: existing imports keep working)
from app.audit.service import AuditEvent, AuditService
from app.authorization.opa_client import OpaClient
from app.core.config import Settings
from app.core.security import RequestContext
from app.repositories import agents as agents_repo
from app.repositories import approvals as approvals_repo
from app.tools.base import ToolConflict, ToolContext, ToolSpec
from app.tools.messages import explain
from app.tools.registry import REGISTRY

log = logging.getLogger("tool_executor")


def _args_hash(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()


class ToolExecutor:
    def __init__(self, opa: OpaClient, audit: AuditService, settings: Settings,
                 registry: dict[str, ToolSpec] | None = None):
        self._opa = opa
        self._audit = audit
        self._settings = settings
        self._registry = registry if registry is not None else REGISTRY

    # ------------------------------------------------------------------------------------------
    def execute(self, ctx: RequestContext, tool_name: str, raw_args: Any, *, agent_id: str | None = None) -> ToolResult:
        p = ctx.principal
        channel = "agent" if agent_id else "api"
        tool_name = str(tool_name)[:64]

        def audit(decision: str, status: str, reason: str, spec: ToolSpec | None = None,
                  resource: dict | None = None, detail: dict | None = None) -> str | None:
            audit_id = self._audit.record(AuditEvent(
                tenant_id=p.tenant_id, user_id=p.user_id, username=p.username, agent_id=agent_id,
                tool_name=tool_name, resource_type=(resource or {}).get("type") or (spec.resource_type if spec else None),
                resource_id=(resource or {}).get("id"), action=(spec.action if spec else "invoke"),
                decision=decision, execution_status=status, reason=reason,
                correlation_id=ctx.correlation_id, channel=channel, detail=detail or {}))
            return str(audit_id) if audit_id else None

        def denied(reasons: list[str], status: str = "denied", spec=None, resource=None, detail=None) -> ToolResult:
            aid = audit("DENY", "NOT_EXECUTED", ",".join(reasons), spec, resource, detail)
            return ToolResult(tool_name, status, False, reasons, f"Denied: {explain(reasons)}.", audit_id=aid)

        # 1 -- tool must be a registered tool
        spec = self._registry.get(tool_name)
        if spec is None:
            return denied(["tool_unknown"])

        # 2 -- strict argument validation (extra fields such as tenant_id are rejected)
        try:
            args = spec.args_model.model_validate(raw_args if isinstance(raw_args, dict) else {})
        except ValidationError as exc:
            fields = sorted({".".join(str(x) for x in e["loc"]) or "arguments" for e in exc.errors()})
            res = denied(["invalid_arguments"], "invalid_arguments", spec, detail={"fields": ",".join(fields)})
            res.message = f"Invalid arguments for {tool_name}: {', '.join(fields)}."
            return res
        args_dict = args.model_dump(mode="json")
        args_hash = _args_hash(args_dict)

        tctx = ToolContext(principal=p, db=ctx.db, opa=self._opa, correlation_id=ctx.correlation_id)

        # 3 -- agent + tool configuration come from the DATABASE
        agent_obj: dict | None = None
        if agent_id:
            agent_row = agents_repo.get_agent(ctx.db, p.tenant_id, agent_id)
            if agent_row is None:
                return denied(["agent_unknown"], spec=spec)
            agent_obj = {"id": agent_row["id"], "enabled": agent_row["enabled"], "tenant_id": agent_row["tenant_id"]}
            cfg = agents_repo.get_tool(ctx.db, p.tenant_id, agent_id, tool_name)
            tool_cfg = {"name": tool_name, "enabled": bool(cfg and cfg["enabled"]),
                        "requires_approval": bool(cfg and cfg["requires_approval"])}
        else:
            tool_cfg = {"name": tool_name, "enabled": True,
                        "requires_approval": agents_repo.tool_requires_approval_anywhere(ctx.db, p.tenant_id, tool_name)}

        # 4 -- target resource, loaded from the DB with an explicit tenant filter (+ RLS)
        try:
            resolved = spec.resolve(tctx, args)
        except Exception:
            ctx.db.rollback()
            log.exception("resolve failed tool=%s", tool_name)
            aid = audit("DENY", "FAILED", "resolve_error", spec)
            return ToolResult(tool_name, "error", False, ["resolve_error"], "The request could not be processed.", audit_id=aid)
        if resolved is None:
            # Same answer for "does not exist" and "belongs to another tenant": no enumeration / IDOR oracle.
            res = denied(["resource_not_found"], "not_found", spec, detail={"requested": json.dumps(args_dict)[:120]})
            res.message = "The requested resource was not found."
            return res
        resource = resolved.resource

        # 5 -- OPA decides. A previously APPROVED human-approval request (bound to these exact args) is
        #      looked up in the DB; the model can't set approval_granted, only the DB can.
        grant = approvals_repo.find(ctx.db, p.tenant_id, status="APPROVED", requester_id=p.user_id,
                                    tool_name=tool_name, resource_type=resource["type"],
                                    resource_id=str(resource["id"]), args_hash=args_hash)
        payload: dict[str, Any] = {
            "subject": p.opa_subject(),
            "action": spec.action,
            "resource": resource,
            "tool": tool_cfg,
            "context": {"channel": channel, "approval_granted": grant is not None,
                        "correlation_id": ctx.correlation_id},
        }
        if agent_obj:
            payload["agent"] = agent_obj
        decision = self._opa.decide_tool(payload)

        # 6 -- deny / human approval gate
        if not decision.allow:
            return denied(list(decision.reasons), "denied", spec, resource)

        if decision.require_human_approval:
            pending = approvals_repo.find(ctx.db, p.tenant_id, status="PENDING", requester_id=p.user_id,
                                          tool_name=tool_name, resource_type=resource["type"],
                                          resource_id=str(resource["id"]), args_hash=args_hash)
            request_id = pending["id"] if pending else approvals_repo.create(
                ctx.db, p.tenant_id, requester_id=p.user_id, agent_id=agent_id, tool_name=tool_name,
                resource_type=resource["type"], resource_id=str(resource["id"]), arguments=args_dict,
                args_hash=args_hash, ttl_minutes=self._settings.approval_ttl_minutes)
            ctx.db.commit()
            aid = audit("PENDING", "PENDING_APPROVAL", "human_approval_required", spec, resource,
                        {"approval_request_id": str(request_id)})
            return ToolResult(tool_name, "pending_approval", True, ["human_approval_required"],
                              "This action needs a human administrator's approval. An approval request was created; "
                              "repeat the request after it has been approved.",
                              approval_request_id=str(request_id), audit_id=aid)

        # 7 -- execute (immediately after the decision), atomically with consuming any approval grant
        try:
            data = spec.execute(tctx, args, resolved)
            if grant is not None and not approvals_repo.mark_executed(ctx.db, p.tenant_id, grant["id"]):
                raise ToolConflict("approval_already_used")
            ctx.db.commit()
        except ToolConflict as exc:
            ctx.db.rollback()
            aid = audit("ALLOW", "FAILED", exc.code, spec, resource)
            return ToolResult(tool_name, "error", True, [exc.code], f"The action could not be completed: {exc.code}.", audit_id=aid)
        except Exception:
            ctx.db.rollback()
            log.exception("tool execution failed tool=%s correlation_id=%s", tool_name, ctx.correlation_id)
            aid = audit("ALLOW", "FAILED", "execution_error", spec, resource)
            return ToolResult(tool_name, "error", True, ["execution_error"],
                              "The action failed. No changes were made.", audit_id=aid)

        # 8 -- audit success
        aid = audit("ALLOW", "SUCCESS", ",".join(decision.reasons), spec, resource)
        return ToolResult(tool_name, "success", True, list(decision.reasons), "OK", data=data, audit_id=aid)
