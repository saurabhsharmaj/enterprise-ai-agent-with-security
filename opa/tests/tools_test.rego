package enterprise.tests

import rego.v1

approve_in(subject, resource) := tool_in(subject, tool_on("approve_invoice"), "approve", resource, agent_a, agent_ctx)

# ---------------------------------------------------------------- allow paths
test_manager_approve_tool_allowed_within_limit if {
	d := data.enterprise.tools.decision with input as approve_in(bob, inv_pending)
	d.allow == true
	d.require_human_approval == false
}

test_search_invoices_tool_allowed_for_employee if {
	i := tool_in(charlie, tool_on("search_invoices"), "search", collection("TENANT_A", "invoice"), agent_a, agent_ctx)
	data.enterprise.tools.allow with input as i
}

test_read_invoice_tool_allowed_for_employee if {
	i := tool_in(charlie, tool_on("read_invoice"), "read", inv_pending, agent_a, agent_ctx)
	data.enterprise.tools.allow with input as i
}

test_search_documents_tool_allowed if {
	i := tool_in(charlie, tool_on("search_documents"), "search", collection("TENANT_A", "document"), agent_a, agent_ctx)
	data.enterprise.tools.allow with input as i
}

test_create_po_tool_allowed_for_manager if {
	i := tool_in(bob, tool_on("create_purchase_order"), "create", po_new(bob, 5000), agent_a, agent_ctx)
	data.enterprise.tools.allow with input as i
}

test_api_channel_needs_no_agent if {
	data.enterprise.tools.allow with input as api_tool_in(bob, "approve_invoice", "approve", inv_pending)
}

# ---------------------------------------------------------------- deny paths
test_employee_denied_approve_tool if {
	not data.enterprise.tools.allow with input as approve_in(charlie, inv_pending)
	"missing_permission" in data.enterprise.tools.deny with input as approve_in(charlie, inv_pending)
}

test_employee_denied_create_po_tool if {
	i := tool_in(charlie, tool_on("create_purchase_order"), "create", po_new(charlie, 10), agent_a, agent_ctx)
	not data.enterprise.tools.allow with input as i
}

test_manager_over_limit_denied_through_tool if {
	not data.enterprise.tools.allow with input as approve_in(bob, inv_large)
	"approval_limit_exceeded" in data.enterprise.tools.deny with input as approve_in(bob, inv_large)
}

test_cross_tenant_denied_through_tool if {
	not data.enterprise.tools.allow with input as approve_in(bob, inv_tenant_b)
	"tenant_mismatch" in data.enterprise.tools.deny with input as approve_in(bob, inv_tenant_b)
}

test_admin_cross_tenant_denied_through_tool if {
	not data.enterprise.tools.allow with input as approve_in(alice, inv_tenant_b)
}

test_unknown_tool_denied if {
	i := tool_in(alice, tool_on("drop_database"), "approve", inv_pending, agent_a, agent_ctx)
	not data.enterprise.tools.allow with input as i
	"tool_unknown" in data.enterprise.tools.deny with input as i
}

test_tool_not_in_agents_catalogue_denied if {
	other_agent := {"id": "OTHER_AGENT", "enabled": true, "tenant_id": "TENANT_A"}
	i := tool_in(bob, tool_on("approve_invoice"), "approve", inv_pending, other_agent, agent_ctx)
	not data.enterprise.tools.allow with input as i
	"tool_not_available_for_agent" in data.enterprise.tools.deny with input as i
}

test_disabled_tool_denied if {
	i := tool_in(bob, tool_off("approve_invoice"), "approve", inv_pending, agent_a, agent_ctx)
	not data.enterprise.tools.allow with input as i
	"tool_disabled" in data.enterprise.tools.deny with input as i
}

test_disabled_agent_denies_every_tool if {
	i := tool_in(bob, tool_on("read_invoice"), "read", inv_pending, agent_a_disabled, agent_ctx)
	not data.enterprise.tools.allow with input as i
	"agent_disabled" in data.enterprise.tools.deny with input as i
}

test_tool_cannot_be_pointed_at_a_different_resource_type if {
	i := tool_in(bob, tool_on("approve_invoice"), "approve", po_new(bob, 10), agent_a, agent_ctx)
	not data.enterprise.tools.allow with input as i
	"tool_action_mismatch" in data.enterprise.tools.deny with input as i
}

test_tool_cannot_be_pointed_at_a_different_action if {
	i := tool_in(charlie, tool_on("read_invoice"), "approve", inv_pending, agent_a, agent_ctx)
	not data.enterprise.tools.allow with input as i
}

test_invalid_channel_denied if {
	i := tool_in(bob, tool_on("read_invoice"), "read", inv_pending, agent_a, {"channel": "cli"})
	not data.enterprise.tools.allow with input as i
	"invalid_channel" in data.enterprise.tools.deny with input as i
}

test_missing_context_denied if {
	i := {"subject": bob, "action": "read", "resource": inv_pending, "tool": tool_on("read_invoice")}
	not data.enterprise.tools.allow with input as i
}

test_agent_channel_without_agent_object_denied if {
	i := {
		"subject": bob, "action": "read", "resource": inv_pending,
		"tool": tool_on("read_invoice"), "context": agent_ctx,
	}
	not data.enterprise.tools.allow with input as i
}

test_tool_policy_denies_empty_input if {
	not data.enterprise.tools.allow with input as {}
}

# ---------------------------------------------------------------- human approval gate
test_high_value_approval_requires_human_signoff_for_manager if {
	d := data.enterprise.tools.decision with input as approve_in(bob, inv_gate)
	d.allow == true
	d.require_human_approval == true
}

test_value_just_below_threshold_needs_no_signoff if {
	just_below := object.union(inv_gate, {"amount": 7999.99})
	d := data.enterprise.tools.decision with input as approve_in(bob, just_below)
	d.allow == true
	d.require_human_approval == false
}

test_granted_approval_clears_the_gate if {
	granted := {"channel": "agent", "approval_granted": true, "correlation_id": "test"}
	i := tool_in(bob, tool_on("approve_invoice"), "approve", inv_gate, agent_a, granted)
	d := data.enterprise.tools.decision with input as i
	d.allow == true
	d.require_human_approval == false
}

test_admin_is_exempt_from_the_gate if {
	d := data.enterprise.tools.decision with input as approve_in(alice, inv_gate)
	d.allow == true
	d.require_human_approval == false
}

test_per_tool_flag_forces_the_gate if {
	i := tool_in(bob, tool_flagged("create_purchase_order"), "create", po_new(bob, 100), agent_a, agent_ctx)
	d := data.enterprise.tools.decision with input as i
	d.allow == true
	d.require_human_approval == true
}

test_gate_never_applies_when_denied if {
	d := data.enterprise.tools.decision with input as approve_in(charlie, inv_gate)
	d.allow == false
	d.require_human_approval == false
}

test_approval_flag_cannot_be_smuggled_in_as_string if {
	forged := {"channel": "agent", "approval_granted": "true", "correlation_id": "test"}
	i := tool_in(bob, tool_on("approve_invoice"), "approve", inv_gate, agent_a, forged)
	d := data.enterprise.tools.decision with input as i
	d.require_human_approval == true
}

test_gate_threshold_comes_from_policy_data if {
	d := data.enterprise.tools.decision with input as approve_in(bob, inv_pending)
		with data.human_approval_thresholds as {"approve_invoice": 1000}
	d.require_human_approval == true
}
