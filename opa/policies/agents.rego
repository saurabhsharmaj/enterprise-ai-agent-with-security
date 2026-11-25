# Agent-level authorization: may THIS user run THIS agent right now?
#
# Input:
#   input.subject = {id, tenant_id, roles[], ...}
#   input.agent   = {id, enabled, tenant_id}     (agent row loaded from the DB by the backend)
#   input.action  = "execute"
package enterprise.agents

import rego.v1

default allow := false

allow if {
	count(deny) == 0
	data.enterprise.authz.valid_subject
	agent_known
	role_permitted
	has_execute_permission
}

agent_known if data.agent_roles[input.agent.id]

agent_enabled if input.agent.enabled == true

agent_in_users_tenant if input.agent.tenant_id == input.subject.tenant_id

# The agent must be allow-listed for at least one of the user's roles.
role_permitted if {
	some role in input.subject.roles
	role in data.agent_roles[input.agent.id]
}

# RBAC permission to execute agents at all.
has_execute_permission if {
	some role in input.subject.roles
	"agent:execute" in data.roles[role].permissions
}

deny contains "invalid_subject" if not data.enterprise.authz.valid_subject

deny contains "agent_unknown" if not agent_known

deny contains "agent_disabled" if not agent_enabled

deny contains "agent_tenant_mismatch" if not agent_in_users_tenant

deny contains "agent_role_not_permitted" if not role_permitted

deny contains "missing_permission" if not has_execute_permission

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
