# Shared fixtures for the policy tests. Mirrors the demo data seeded by the backend.
package enterprise.tests

import rego.v1

alice := {
	"id": "11111111-1111-4111-8111-111111111111", "username": "alice", "tenant_id": "TENANT_A",
	"roles": ["ADMIN"], "department": "IT", "approval_limit": 100000, "groups": ["IT"],
}

bob := {
	"id": "22222222-2222-4222-8222-222222222222", "username": "bob", "tenant_id": "TENANT_A",
	"roles": ["MANAGER"], "department": "FINANCE", "approval_limit": 10000, "groups": ["FINANCE"],
}

charlie := {
	"id": "33333333-3333-4333-8333-333333333333", "username": "charlie", "tenant_id": "TENANT_A",
	"roles": ["EMPLOYEE"], "department": "FINANCE", "approval_limit": 0, "groups": ["FINANCE"],
}

david := {
	"id": "44444444-4444-4444-8444-444444444444", "username": "david", "tenant_id": "TENANT_B",
	"roles": ["MANAGER"], "department": "FINANCE", "approval_limit": 5000, "groups": ["FINANCE"],
}

clerk_b_id := "55555555-5555-4555-8555-555555555555"

inv_pending := {
	"type": "invoice", "id": "INV-1001", "tenant_id": "TENANT_A", "department": "FINANCE",
	"owner_id": charlie.id, "status": "PENDING", "classification": "INTERNAL", "amount": 4500,
}

inv_large := object.union(inv_pending, {"id": "INV-1002", "amount": 12000})

inv_gate := object.union(inv_pending, {"id": "INV-1003", "amount": 9000})

inv_approved := object.union(inv_pending, {"id": "INV-1004", "status": "APPROVED"})

inv_confidential := object.union(inv_pending, {
	"id": "INV-1005", "classification": "CONFIDENTIAL", "owner_id": bob.id, "amount": 7000,
})

inv_it := object.union(inv_pending, {"id": "INV-1006", "department": "IT", "owner_id": alice.id})

inv_tenant_b := {
	"type": "invoice", "id": "INV-2001", "tenant_id": "TENANT_B", "department": "FINANCE",
	"owner_id": clerk_b_id, "status": "PENDING", "classification": "INTERNAL", "amount": 3000,
}

inv_tenant_b_at_limit := object.union(inv_tenant_b, {"id": "INV-2003", "amount": 5000})

collection(tenant, rtype) := {"type": rtype, "id": "*", "tenant_id": tenant, "scope": "collection"}

po_new(user, amount) := {
	"type": "purchase_order", "id": "NEW", "tenant_id": user.tenant_id, "department": user.department,
	"owner_id": user.id, "status": "SUBMITTED", "amount": amount,
}

approval_request(requester, status) := {
	"type": "approval_request", "id": "req-1", "tenant_id": "TENANT_A",
	"requester_id": requester.id, "status": status,
}

agent_a := {"id": "FINANCE_AGENT", "enabled": true, "tenant_id": "TENANT_A"}

agent_a_disabled := {"id": "FINANCE_AGENT", "enabled": false, "tenant_id": "TENANT_A"}

agent_b := {"id": "FINANCE_AGENT", "enabled": true, "tenant_id": "TENANT_B"}

tool_on(name) := {"name": name, "enabled": true, "requires_approval": false}

tool_off(name) := {"name": name, "enabled": false, "requires_approval": false}

tool_flagged(name) := {"name": name, "enabled": true, "requires_approval": true}

agent_ctx := {"channel": "agent", "approval_granted": false, "correlation_id": "test"}

api_ctx := {"channel": "api", "approval_granted": false, "correlation_id": "test"}

authz_in(subject, action, resource) := {"subject": subject, "action": action, "resource": resource}

tool_in(subject, tool_cfg, action, resource, agent, ctx) := {
	"subject": subject, "action": action, "resource": resource,
	"tool": tool_cfg, "agent": agent, "context": ctx,
}

api_tool_in(subject, tool, action, resource) := {
	"subject": subject, "action": action, "resource": resource,
	"tool": tool_on(tool), "context": api_ctx,
}
