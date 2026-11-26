# Policy tests for the RAG tool and permission-filtered retrieval (documents).
package enterprise.tests

import rego.v1

doc(id, tenant, dept, cls) := {
	"type": "document", "id": id, "tenant_id": tenant, "department": dept,
	"owner_id": alice.id, "classification": cls,
}

doc_internal := doc("d1", "TENANT_A", "FINANCE", "INTERNAL")

doc_confidential := doc("d2", "TENANT_A", "FINANCE", "CONFIDENTIAL")

doc_restricted := doc("d3", "TENANT_A", "FINANCE", "RESTRICTED")

doc_it := doc("d4", "TENANT_A", "IT", "INTERNAL")

doc_other_tenant := doc("d5", "TENANT_B", "FINANCE", "INTERNAL")

all_docs := [doc_internal, doc_confidential, doc_restricted, doc_it, doc_other_tenant]

test_ask_documents_tool_allowed_for_every_role if {
	every u in [alice, bob, charlie] {
		i := tool_in(u, tool_on("ask_documents"), "search", collection("TENANT_A", "document"), agent_a, agent_ctx)
		data.enterprise.tools.allow with input as i
	}
}

test_ask_documents_tool_denied_across_tenants if {
	i := tool_in(david, tool_on("ask_documents"), "search", collection("TENANT_A", "document"), agent_a, agent_ctx)
	not data.enterprise.tools.allow with input as i
}

test_rag_filter_employee_sees_only_internal_in_own_department if {
	ids := data.enterprise.authz.allowed_ids with input as {"subject": charlie, "action": "read", "resources": all_docs}
	ids == {"d1"}
}

test_rag_filter_manager_also_sees_confidential if {
	ids := data.enterprise.authz.allowed_ids with input as {"subject": bob, "action": "read", "resources": all_docs}
	ids == {"d1", "d2"}
}

test_rag_filter_admin_sees_restricted_but_never_other_tenant if {
	ids := data.enterprise.authz.allowed_ids with input as {"subject": alice, "action": "read", "resources": all_docs}
	ids == {"d1", "d2", "d3", "d4"}
}

test_rag_filter_other_tenant_manager_sees_only_own_tenant if {
	ids := data.enterprise.authz.allowed_ids with input as {"subject": david, "action": "read", "resources": all_docs}
	ids == {"d5"}
}

test_document_create_permission_for_manager_not_employee if {
	data.enterprise.authz.allow with input as authz_in(bob, "create", collection("TENANT_A", "document"))
	not data.enterprise.authz.allow with input as authz_in(charlie, "create", collection("TENANT_A", "document"))
}

new_doc(user, dept, cls) := {
	"type": "document", "id": "NEW", "tenant_id": user.tenant_id, "department": dept,
	"owner_id": user.id, "classification": cls,
}

test_create_document_in_own_department_allowed_for_manager if {
	data.enterprise.authz.allow with input as authz_in(bob, "create", new_doc(bob, "FINANCE", "INTERNAL"))
	data.enterprise.authz.allow with input as authz_in(bob, "create", new_doc(bob, "FINANCE", "CONFIDENTIAL"))
}

test_create_document_cannot_exceed_clearance if {
	not data.enterprise.authz.allow with input as authz_in(bob, "create", new_doc(bob, "FINANCE", "RESTRICTED"))
	data.enterprise.authz.allow with input as authz_in(alice, "create", new_doc(alice, "IT", "RESTRICTED"))
}

test_create_document_in_other_department_denied_for_manager if {
	not data.enterprise.authz.allow with input as authz_in(bob, "create", new_doc(bob, "IT", "INTERNAL"))
}

test_create_document_in_other_tenant_denied if {
	not data.enterprise.authz.allow with input as authz_in(alice, "create", new_doc(david, "FINANCE", "INTERNAL"))
	not data.enterprise.authz.allow with input as authz_in(bob, "create", object.union(new_doc(bob, "FINANCE", "INTERNAL"), {"tenant_id": "TENANT_B"}))
}

test_employee_cannot_create_documents if {
	not data.enterprise.authz.allow with input as authz_in(charlie, "create", new_doc(charlie, "FINANCE", "INTERNAL"))
}
