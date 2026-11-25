package enterprise.tests

import rego.v1

agent_in(subject, agent) := {"subject": subject, "agent": agent, "action": "execute"}

test_employee_may_run_enabled_agent_in_own_tenant if {
	data.enterprise.agents.allow with input as agent_in(charlie, agent_a)
}

test_manager_and_admin_may_run_agent if {
	data.enterprise.agents.allow with input as agent_in(bob, agent_a)
	data.enterprise.agents.allow with input as agent_in(alice, agent_a)
}

test_disabled_agent_cannot_execute if {
	not data.enterprise.agents.allow with input as agent_in(bob, agent_a_disabled)
	"agent_disabled" in data.enterprise.agents.deny with input as agent_in(bob, agent_a_disabled)
}

test_agent_from_another_tenant_cannot_execute if {
	not data.enterprise.agents.allow with input as agent_in(bob, agent_b)
	"agent_tenant_mismatch" in data.enterprise.agents.deny with input as agent_in(bob, agent_b)
}

test_unknown_agent_denied if {
	ghost := {"id": "ROGUE_AGENT", "enabled": true, "tenant_id": "TENANT_A"}
	not data.enterprise.agents.allow with input as agent_in(bob, ghost)
	"agent_unknown" in data.enterprise.agents.deny with input as agent_in(bob, ghost)
}

test_unknown_role_cannot_run_agent if {
	outsider := object.union(bob, {"roles": ["CONTRACTOR"]})
	not data.enterprise.agents.allow with input as agent_in(outsider, agent_a)
}

test_agent_policy_denies_empty_input if {
	not data.enterprise.agents.allow with input as {}
}

test_agent_enabled_flag_must_be_boolean_true if {
	sneaky := object.union(agent_a, {"enabled": "true"})
	not data.enterprise.agents.allow with input as agent_in(bob, sneaky)
}
