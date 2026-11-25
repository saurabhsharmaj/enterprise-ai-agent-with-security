# Generic resource authorization: RBAC + ABAC.  Deny-by-default.
#
# Input contract (built ONLY by the backend, never by the frontend or the LLM):
#   input.subject  = {id, username, tenant_id, roles[], department, approval_limit, groups[]}
#   input.action   = "read" | "search" | "approve" | "create" | "decide" | ...
#   input.resource = {type, id, tenant_id, scope?, department?, owner_id?, status?,
#                     classification?, amount?, requester_id?}
#
# Design rule: every REQUIRED fact is expressed as a positive condition (tenant_ok, rbac_allowed,
# ...) and a deny reason is raised when it is NOT true.  `not <undefined>` is true in Rego, so a
# missing attribute can never silently become an allow.
package enterprise.authz

import rego.v1

default allow := false

# --------------------------------------------------------------------------------------------
# Final decision. Every term below must hold; belt and braces on top of count(deny) == 0.
# --------------------------------------------------------------------------------------------
allow if {
	count(deny) == 0
	valid_subject
	rbac_allowed
	tenant_ok
}

# --------------------------------------------------------------------------------------------
# A. RBAC: role -> "resource_type:action" permission (data.json is the single source of truth)
# --------------------------------------------------------------------------------------------
required_permission := concat(":", [input.resource.type, input.action])

rbac_allowed if {
	some role in input.subject.roles
	required_permission in data.roles[role].permissions
}

deny contains "missing_permission" if not rbac_allowed

# --------------------------------------------------------------------------------------------
# Subject sanity: a malformed subject is denied outright (also blocks null == null tricks).
# --------------------------------------------------------------------------------------------
valid_subject if {
	is_string(input.subject.id)
	input.subject.id != ""
	is_string(input.subject.tenant_id)
	input.subject.tenant_id != ""
	is_array(input.subject.roles)
}

deny contains "invalid_subject" if not valid_subject

is_admin if "ADMIN" in input.subject.roles

# --------------------------------------------------------------------------------------------
# B1. ABAC: tenant isolation.  Even ADMIN is confined to their tenant unless data.json holds an
#     explicit cross-tenant grant: {"cross_tenant_grants": {"<user-id>": ["TENANT_B"]}}.
# --------------------------------------------------------------------------------------------
tenant_ok if input.resource.tenant_id == input.subject.tenant_id

tenant_ok if {
	is_admin
	input.resource.tenant_id in data.cross_tenant_grants[input.subject.id]
}

deny contains "tenant_mismatch" if not tenant_ok

# --------------------------------------------------------------------------------------------
# Collection scope (e.g. "search"): row-level attributes are enforced afterwards, per row, via
# the `allowed_ids` filter below.
# --------------------------------------------------------------------------------------------
is_collection if input.resource.scope == "collection"

deny contains "invalid_scope" if {
	is_collection
	input.action in data.non_collection_actions
}

# --------------------------------------------------------------------------------------------
# B2. ABAC: department (admins see all departments of their tenant; others: own department
#     or resources they own)
# --------------------------------------------------------------------------------------------
department_scoped if input.resource.type in data.department_scoped_types

department_ok if is_admin

department_ok if input.resource.department == input.subject.department

department_ok if input.resource.owner_id == input.subject.id

deny contains "department_mismatch" if {
	department_scoped
	not is_collection
	not department_ok
}

# --------------------------------------------------------------------------------------------
# B3. ABAC: classification vs. role clearance
# --------------------------------------------------------------------------------------------
classified if input.resource.type in data.classified_types

clearance := max({lvl |
	some role in input.subject.roles
	lvl := data.clearance[role]
})

clearance_ok if data.classification_levels[input.resource.classification] <= clearance

deny contains "insufficient_clearance" if {
	classified
	not is_collection
	not clearance_ok
}

# --------------------------------------------------------------------------------------------
# B4. ABAC business rules: invoice approval
#     status must be PENDING, amount <= approval limit (from the trusted DB), no self-approval.
#     The "cannot be approved twice" rule is the PENDING check (+ an atomic guarded UPDATE).
# --------------------------------------------------------------------------------------------
is_invoice_approval if {
	input.resource.type == "invoice"
	input.action == "approve"
}

invoice_pending if input.resource.status == "PENDING"

within_limit if input.resource.amount <= input.subject.approval_limit

owner_is_other if input.resource.owner_id != input.subject.id

deny contains "invoice_not_pending" if {
	is_invoice_approval
	not invoice_pending
}

deny contains "approval_limit_exceeded" if {
	is_invoice_approval
	not within_limit
}

deny contains "self_approval_forbidden" if {
	is_invoice_approval
	not owner_is_other
}

# --------------------------------------------------------------------------------------------
# B5. ABAC business rules: purchase order creation is capped by the same trusted limit
# --------------------------------------------------------------------------------------------
is_po_create if {
	input.resource.type == "purchase_order"
	input.action == "create"
}

positive_amount if input.resource.amount > 0

deny contains "approval_limit_exceeded" if {
	is_po_create
	not within_limit
}

deny contains "invalid_amount" if {
	is_po_create
	not positive_amount
}

# --------------------------------------------------------------------------------------------
# B6. Separation of duties for human-approval gates
# --------------------------------------------------------------------------------------------
is_decision if {
	input.resource.type == "approval_request"
	input.action == "decide"
}

request_pending if input.resource.status == "PENDING"

requester_is_other if input.resource.requester_id != input.subject.id

deny contains "request_not_pending" if {
	is_decision
	not request_pending
}

deny contains "self_decision_forbidden" if {
	is_decision
	not requester_is_other
}

# --------------------------------------------------------------------------------------------
# Row-level filter used after a collection-level `search` is authorised:
# returns the ids of the candidate rows the subject may `read` (same rules as a single read).
# input.resources = [<resource>, ...], input.action = "read"
# --------------------------------------------------------------------------------------------
allowed_ids contains r.id if {
	some r in input.resources
	allow with input as {"subject": input.subject, "action": input.action, "resource": r}
}

# --------------------------------------------------------------------------------------------
# Decision document returned to the backend
# --------------------------------------------------------------------------------------------
reasons := sort(deny) if count(deny) > 0

reasons := ["allowed_by_policy"] if {
	count(deny) == 0
	allow
}

reasons := ["denied_by_default"] if {
	count(deny) == 0
	not allow
}

decision := {"allow": allow, "reasons": reasons}
