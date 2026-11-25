# Tool-level authorization: evaluated for EVERY tool invocation, immediately before execution.
#
# Composes the agent policy and the resource policy, then adds tool-specific checks and the
# human-approval gate.
#
# Input:
#   input.subject, input.action, input.resource   - see authz.rego
#   input.agent   = {id, enabled, tenant_id}      - only when channel == "agent"
#   input.tool    = {name, enabled, requires_approval}
#   input.context = {channel: "agent" | "api", approval_granted: bool, correlation_id}
#
# `context.approval_granted` is set ONLY by the backend's approval service after it has verified
# a signed-off approval record in the database. The LLM cannot influence it.
package enterprise.tools

import rego.v1

default allow := false

default require_human_approval := false

spec := data.tools[input.tool.name]

valid_channel if input.context.channel in {"agent", "api"}

agent_channel if input.context.channel == "agent"

# The backend derives (resource type, action) from its tool registry; the policy independently
# checks they match the policy's own tool catalogue.
tool_matches_spec if {
	spec.action == input.action
	spec.resource_type == input.resource.type
}

tool_in_agent if input.tool.name in data.agent_tools[input.agent.id]

tool_enabled if input.tool.enabled == true

agent_ok if not agent_channel

agent_ok if {
	agent_channel
	data.enterprise.agents.allow
}

allow if {
	count(deny) == 0
	valid_channel
	tool_matches_spec
	agent_ok
	data.enterprise.authz.allow
}

deny contains "invalid_channel" if not valid_channel

deny contains "tool_unknown" if not spec

deny contains "tool_action_mismatch" if not tool_matches_spec

deny contains "tool_not_available_for_agent" if {
	agent_channel
	not tool_in_agent
}

deny contains "tool_disabled" if {
	agent_channel
	not tool_enabled
}

# Reasons from the agent policy (agent channel only) and the resource policy (always).
deny contains reason if {
	agent_channel
	some reason in data.enterprise.agents.deny
}

deny contains reason if {
	some reason in data.enterprise.authz.deny
}

# --------------------------------------------------------------------------------------------
# Human approval gate ("configurable high-risk actions")
#   1. per-tool switch stored in the database (agent_tools.requires_approval), or
#   2. policy data threshold on the amount (data.human_approval_thresholds)
# ADMINs are exempt (they are the approvers); a granted approval clears the gate.
# --------------------------------------------------------------------------------------------
gated if input.tool.requires_approval == true

gated if {
	threshold := data.human_approval_thresholds[input.tool.name]
	input.resource.amount >= threshold
}

require_human_approval if {
	allow
	gated
	not input.context.approval_granted == true
	not "ADMIN" in input.subject.roles
}

reasons := sort(deny) if count(deny) > 0

reasons := ["allowed_by_policy"] if {
	count(deny) == 0
	allow
}

reasons := ["denied_by_default"] if {
	count(deny) == 0
	not allow
}

decision := {
	"allow": allow,
	"reasons": reasons,
	"require_human_approval": require_human_approval,
}
