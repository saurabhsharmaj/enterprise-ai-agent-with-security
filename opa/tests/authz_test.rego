package enterprise.tests

import rego.v1

# ---------------------------------------------------------------- RBAC / positive scenarios
test_admin_reads_any_department_invoice_in_own_tenant if {
	data.enterprise.authz.allow with input as authz_in(alice, "read", inv_pending)
}

test_admin_reads_confidential_invoice if {
	data.enterprise.authz.allow with input as authz_in(alice, "read", inv_confidential)
}

test_manager_reads_own_department_confidential_invoice if {
	data.enterprise.authz.allow with input as authz_in(bob, "read", inv_confidential)
}

test_employee_reads_own_department_internal_invoice if {
	data.enterprise.authz.allow with input as authz_in(charlie, "read", inv_pending)
}

test_employee_can_search_invoices_collection if {
	data.enterprise.authz.allow with input as authz_in(charlie, "search", collection("TENANT_A", "invoice"))
}

test_employee_can_search_documents_collection if {
	data.enterprise.authz.allow with input as authz_in(charlie, "search", collection("TENANT_A", "document"))
}

# ---------------------------------------------------------------- RBAC / negative scenarios
test_employee_cannot_approve_invoices if {
	not data.enterprise.authz.allow with input as authz_in(charlie, "approve", inv_pending)
	"missing_permission" in data.enterprise.authz.deny with input as authz_in(charlie, "approve", inv_pending)
}

test_employee_cannot_create_purchase_orders if {
	not data.enterprise.authz.allow with input as authz_in(charlie, "create", po_new(charlie, 100))
}

test_employee_cannot_manage_users if {
	not data.enterprise.authz.allow with input as authz_in(charlie, "read", collection("TENANT_A", "user"))
}

test_manager_cannot_read_audit_logs if {
	not data.enterprise.authz.allow with input as authz_in(bob, "read", collection("TENANT_A", "audit"))
}

test_admin_reads_audit_logs if {
	data.enterprise.authz.allow with input as authz_in(alice, "read", collection("TENANT_A", "audit"))
}

test_unknown_role_denied if {
	ghost := object.union(bob, {"roles": ["SUPERUSER"]})
	not data.enterprise.authz.allow with input as authz_in(ghost, "read", inv_pending)
}

test_empty_input_is_denied_by_default if {
	not data.enterprise.authz.allow with input as {}
}

test_subject_without_roles_denied if {
	nobody := object.union(bob, {"roles": []})
	not data.enterprise.authz.allow with input as authz_in(nobody, "read", inv_pending)
}

test_malformed_subject_denied if {
	broken := {"id": null, "tenant_id": null, "roles": ["ADMIN"]}
	res := object.union(inv_pending, {"tenant_id": null})
	not data.enterprise.authz.allow with input as authz_in(broken, "read", res)
}

# ---------------------------------------------------------------- ABAC: department / classification
test_manager_denied_other_department if {
	not data.enterprise.authz.allow with input as authz_in(bob, "read", inv_it)
	"department_mismatch" in data.enterprise.authz.deny with input as authz_in(bob, "read", inv_it)
}

test_owner_may_read_own_resource_in_other_department if {
	mine := object.union(inv_it, {"owner_id": bob.id})
	data.enterprise.authz.allow with input as authz_in(bob, "read", mine)
}

test_employee_denied_confidential_invoice if {
	not data.enterprise.authz.allow with input as authz_in(charlie, "read", inv_confidential)
	"insufficient_clearance" in data.enterprise.authz.deny with input as authz_in(charlie, "read", inv_confidential)
}

test_missing_classification_is_denied if {
	res := {"type": "invoice", "id": "X", "tenant_id": "TENANT_A", "department": "FINANCE", "owner_id": charlie.id}
	not data.enterprise.authz.allow with input as authz_in(charlie, "read", res)
}

# ---------------------------------------------------------------- Tenant isolation
test_admin_cannot_read_other_tenant_invoice if {
	not data.enterprise.authz.allow with input as authz_in(alice, "read", inv_tenant_b)
	"tenant_mismatch" in data.enterprise.authz.deny with input as authz_in(alice, "read", inv_tenant_b)
}

test_manager_cannot_read_other_tenant_invoice if {
	not data.enterprise.authz.allow with input as authz_in(david, "read", inv_pending)
	"tenant_mismatch" in data.enterprise.authz.deny with input as authz_in(david, "read", inv_pending)
}

test_cross_tenant_collection_search_denied if {
	not data.enterprise.authz.allow with input as authz_in(bob, "search", collection("TENANT_B", "invoice"))
}

test_explicit_cross_tenant_grant_lets_admin_through if {
	data.enterprise.authz.allow with input as authz_in(alice, "read", inv_tenant_b)
		with data.cross_tenant_grants as {alice.id: ["TENANT_B"]}
}

test_cross_tenant_grant_is_per_tenant if {
	not data.enterprise.authz.allow with input as authz_in(alice, "read", object.union(inv_tenant_b, {"tenant_id": "TENANT_C"}))
		with data.cross_tenant_grants as {alice.id: ["TENANT_B"]}
}

test_cross_tenant_grant_does_not_help_non_admins if {
	not data.enterprise.authz.allow with input as authz_in(bob, "read", inv_tenant_b)
		with data.cross_tenant_grants as {bob.id: ["TENANT_B"]}
}

# ---------------------------------------------------------------- Approval rules and limits
test_manager_approves_within_limit if {
	data.enterprise.authz.allow with input as authz_in(bob, "approve", inv_pending)
}

test_manager_denied_above_limit if {
	not data.enterprise.authz.allow with input as authz_in(bob, "approve", inv_large)
	"approval_limit_exceeded" in data.enterprise.authz.deny with input as authz_in(bob, "approve", inv_large)
}

test_limit_is_inclusive if {
	data.enterprise.authz.allow with input as authz_in(david, "approve", inv_tenant_b_at_limit)
}

test_limit_is_per_user if {
	# 7000 is above David's 5000 limit but below Bob's 10000
	over_for_david := object.union(inv_tenant_b, {"amount": 7000})
	not data.enterprise.authz.allow with input as authz_in(david, "approve", over_for_david)
	data.enterprise.authz.allow with input as authz_in(bob, "approve", inv_confidential_other_owner)
}

inv_confidential_other_owner := object.union(inv_confidential, {"owner_id": charlie.id})

test_missing_amount_is_denied if {
	res := {
		"type": "invoice", "id": "X", "tenant_id": "TENANT_A", "department": "FINANCE",
		"owner_id": charlie.id, "status": "PENDING", "classification": "INTERNAL",
	}
	not data.enterprise.authz.allow with input as authz_in(bob, "approve", res)
}

test_missing_approval_limit_is_denied if {
	no_limit := {"id": bob.id, "tenant_id": "TENANT_A", "roles": ["MANAGER"], "department": "FINANCE"}
	not data.enterprise.authz.allow with input as authz_in(no_limit, "approve", inv_pending)
}

test_cannot_approve_twice if {
	not data.enterprise.authz.allow with input as authz_in(bob, "approve", inv_approved)
	"invoice_not_pending" in data.enterprise.authz.deny with input as authz_in(bob, "approve", inv_approved)
}

test_cannot_approve_own_invoice if {
	not data.enterprise.authz.allow with input as authz_in(bob, "approve", inv_confidential)
	"self_approval_forbidden" in data.enterprise.authz.deny with input as authz_in(bob, "approve", inv_confidential)
}

test_missing_owner_blocks_approval if {
	res := object.remove(inv_pending, ["owner_id"])
	not data.enterprise.authz.allow with input as authz_in(bob, "approve", res)
}

test_approve_requires_a_concrete_resource if {
	not data.enterprise.authz.allow with input as authz_in(bob, "approve", collection("TENANT_A", "invoice"))
	"invalid_scope" in data.enterprise.authz.deny with input as authz_in(bob, "approve", collection("TENANT_A", "invoice"))
}

# ---------------------------------------------------------------- Purchase orders
test_manager_creates_po_within_limit if {
	data.enterprise.authz.allow with input as authz_in(bob, "create", po_new(bob, 5000))
}

test_manager_cannot_create_po_above_limit if {
	not data.enterprise.authz.allow with input as authz_in(bob, "create", po_new(bob, 10000.01))
	"approval_limit_exceeded" in data.enterprise.authz.deny with input as authz_in(bob, "create", po_new(bob, 10000.01))
}

test_david_po_limit_is_five_thousand if {
	data.enterprise.authz.allow with input as authz_in(david, "create", po_new(david, 5000))
	not data.enterprise.authz.allow with input as authz_in(david, "create", po_new(david, 5001))
}

test_po_must_be_positive if {
	not data.enterprise.authz.allow with input as authz_in(bob, "create", po_new(bob, 0))
}

test_po_cannot_be_created_in_other_tenant if {
	elsewhere := object.union(po_new(bob, 100), {"tenant_id": "TENANT_B"})
	not data.enterprise.authz.allow with input as authz_in(bob, "create", elsewhere)
}

# ---------------------------------------------------------------- Separation of duties
test_admin_decides_someone_elses_request if {
	data.enterprise.authz.allow with input as authz_in(alice, "decide", approval_request(bob, "PENDING"))
}

test_requester_cannot_decide_own_request if {
	not data.enterprise.authz.allow with input as authz_in(alice, "decide", approval_request(alice, "PENDING"))
	"self_decision_forbidden" in data.enterprise.authz.deny with input as authz_in(alice, "decide", approval_request(alice, "PENDING"))
}

test_manager_cannot_decide_requests if {
	not data.enterprise.authz.allow with input as authz_in(bob, "decide", approval_request(charlie, "PENDING"))
}

test_cannot_decide_a_closed_request if {
	not data.enterprise.authz.allow with input as authz_in(alice, "decide", approval_request(bob, "EXECUTED"))
	"request_not_pending" in data.enterprise.authz.deny with input as authz_in(alice, "decide", approval_request(bob, "EXECUTED"))
}

# ---------------------------------------------------------------- Row-level filter
test_filter_returns_only_permitted_rows_for_employee if {
	ids := data.enterprise.authz.allowed_ids with input as {
		"subject": charlie, "action": "read",
		"resources": [inv_pending, inv_confidential, inv_it, inv_tenant_b],
	}
	ids == {"INV-1001"}
}

test_filter_for_manager if {
	ids := data.enterprise.authz.allowed_ids with input as {
		"subject": bob, "action": "read",
		"resources": [inv_pending, inv_confidential, inv_it, inv_tenant_b],
	}
	ids == {"INV-1001", "INV-1005"}
}

test_filter_for_admin_still_stops_at_tenant_border if {
	ids := data.enterprise.authz.allowed_ids with input as {
		"subject": alice, "action": "read",
		"resources": [inv_pending, inv_confidential, inv_it, inv_tenant_b],
	}
	ids == {"INV-1001", "INV-1005", "INV-1006"}
}

test_filter_with_empty_input_returns_nothing if {
	ids := data.enterprise.authz.allowed_ids with input as {}
	count(ids) == 0
}

# ---------------------------------------------------------------- Decision document
test_decision_document_shape if {
	d := data.enterprise.authz.decision with input as authz_in(bob, "approve", inv_large)
	d.allow == false
	"approval_limit_exceeded" in d.reasons
}

test_decision_document_for_allow if {
	d := data.enterprise.authz.decision with input as authz_in(bob, "approve", inv_pending)
	d.allow == true
	d.reasons == ["allowed_by_policy"]
}
