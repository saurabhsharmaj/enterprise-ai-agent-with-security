# Protects OPA's own REST API (service-to-service security).
# OPA runs with --authentication=token --authorization=basic, so every request is evaluated here.
#
#  * GET /health            -> open (container health check)
#  * POST /v1/data/enterprise/** -> only with the backend's bearer token
#  * everything else (policy upload, data writes, /v1/data root dump, ...) -> denied
#
# The token itself is injected at container start (see docker-compose.yml) as data.opa_service_token.
package system.authz

import rego.v1

default allow := false

allow if {
	input.method == "GET"
	input.path == ["health"]
}

allow if {
	input.method == "POST"
	input.path[0] == "v1"
	input.path[1] == "data"
	input.path[2] == "enterprise"
	token_ok
}

token_ok if {
	is_string(data.opa_service_token)
	count(data.opa_service_token) >= 32
	input.identity == data.opa_service_token
}
