package enterprise.tests

import rego.v1

token := "0123456789abcdef0123456789abcdef0123456789abcdef"

decision_request(identity) := {
	"method": "POST",
	"path": ["v1", "data", "enterprise", "tools", "decision"],
	"identity": identity,
}

test_health_is_open if {
	data.system.authz.allow with input as {"method": "GET", "path": ["health"]}
}

test_backend_token_may_query_enterprise_policies if {
	data.system.authz.allow with input as decision_request(token)
		with data.opa_service_token as token
}

test_wrong_token_denied if {
	not data.system.authz.allow with input as decision_request("wrong-token-wrong-token-wrong-token-wrong")
		with data.opa_service_token as token
}

test_missing_token_denied if {
	not data.system.authz.allow with input as {
		"method": "POST",
		"path": ["v1", "data", "enterprise", "tools", "decision"],
	}
		with data.opa_service_token as token
}

test_token_cannot_dump_the_data_root if {
	not data.system.authz.allow with input as {"method": "GET", "path": ["v1", "data"], "identity": token}
		with data.opa_service_token as token
}

test_token_cannot_read_policy_data_directly_via_get if {
	not data.system.authz.allow with input as {"method": "GET", "path": ["v1", "data", "enterprise"], "identity": token}
		with data.opa_service_token as token
}

test_token_cannot_overwrite_policies if {
	not data.system.authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "authz"], "identity": token}
		with data.opa_service_token as token
}

test_token_cannot_write_data if {
	not data.system.authz.allow with input as {"method": "PUT", "path": ["v1", "data", "enterprise", "roles"], "identity": token}
		with data.opa_service_token as token
}

test_token_cannot_query_outside_enterprise_namespace if {
	not data.system.authz.allow with input as {"method": "POST", "path": ["v1", "data", "system"], "identity": token}
		with data.opa_service_token as token
}

test_too_short_configured_token_disables_access if {
	weak := "short"
	not data.system.authz.allow with input as decision_request(weak)
		with data.opa_service_token as weak
}

test_no_configured_token_denies_everything_but_health if {
	not data.system.authz.allow with input as decision_request(token)
}
