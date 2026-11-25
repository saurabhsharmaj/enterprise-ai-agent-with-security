"""Human-readable text for policy reason codes (UI + chat). Codes come from the Rego policies."""
REASON_TEXT = {
    "missing_permission": "your role does not have the required permission",
    "tenant_mismatch": "the resource belongs to a different tenant",
    "department_mismatch": "the resource belongs to a different department",
    "insufficient_clearance": "the resource classification is above your clearance",
    "approval_limit_exceeded": "the amount is above your approval limit",
    "invoice_not_pending": "the invoice is not in PENDING status (it may already be approved)",
    "self_approval_forbidden": "you cannot approve an invoice you own",
    "self_decision_forbidden": "you cannot decide your own approval request",
    "request_not_pending": "the approval request is no longer pending",
    "invalid_amount": "the amount must be greater than zero",
    "invalid_scope": "this operation needs a specific resource",
    "invalid_subject": "your identity context is incomplete",
    "agent_disabled": "the agent is disabled",
    "agent_unknown": "the agent does not exist or is not allow-listed",
    "agent_tenant_mismatch": "the agent belongs to a different tenant",
    "agent_role_not_permitted": "your role may not use this agent",
    "tool_unknown": "the tool is unknown",
    "tool_disabled": "the tool is disabled for this agent",
    "tool_not_available_for_agent": "the tool is not part of this agent's catalogue",
    "tool_action_mismatch": "the tool does not match the requested action",
    "invalid_channel": "invalid invocation channel",
    "invalid_arguments": "the tool arguments are invalid",
    "resource_not_found": "the resource was not found",
    "opa_unavailable": "the authorisation service is unavailable (failing closed)",
    "opa_undefined_result": "the authorisation service returned no decision (failing closed)",
    "denied_by_default": "no policy allows this action",
}


def explain(reasons: list[str] | tuple[str, ...]) -> str:
    return "; ".join(REASON_TEXT.get(r, r) for r in reasons) or REASON_TEXT["denied_by_default"]
