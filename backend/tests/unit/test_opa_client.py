"""The OPA client must FAIL CLOSED: anything but a clean, explicit `allow: true` is a deny."""
import httpx

from app.authorization.opa_client import OpaClient
from tests.conftest import SETTINGS


def client_with(handler) -> OpaClient:
    return OpaClient(SETTINGS, transport=httpx.MockTransport(handler))


PAYLOAD = {"subject": {}, "action": "read", "resource": {}}


def test_explicit_allow():
    c = client_with(lambda req: httpx.Response(200, json={"result": {"allow": True, "reasons": ["allowed_by_policy"],
                                                                      "require_human_approval": False}}))
    d = c.decide_tool(PAYLOAD)
    assert d.allow and not d.require_human_approval


def test_explicit_deny_keeps_reasons():
    c = client_with(lambda req: httpx.Response(200, json={"result": {"allow": False, "reasons": ["tenant_mismatch"]}}))
    d = c.decide_tool(PAYLOAD)
    assert not d.allow and d.reasons == ("tenant_mismatch",)


def test_gate_flag_is_ignored_when_denied():
    c = client_with(lambda req: httpx.Response(200, json={"result": {"allow": False, "require_human_approval": True}}))
    assert not c.decide_tool(PAYLOAD).require_human_approval


def test_opa_unreachable_is_deny():
    def boom(req):
        raise httpx.ConnectError("refused")

    d = client_with(boom).decide_tool(PAYLOAD)
    assert not d.allow and d.reasons == ("opa_unavailable",)


def test_opa_timeout_is_deny():
    def slow(req):
        raise httpx.ReadTimeout("slow")

    assert not client_with(slow).decide_resource({}, "read", {}).allow


def test_opa_server_error_is_deny():
    assert not client_with(lambda req: httpx.Response(500, text="boom")).decide_agent({}, {}).allow


def test_opa_unauthorized_is_deny():
    assert not client_with(lambda req: httpx.Response(401, json={"code": "unauthorized"})).decide_tool(PAYLOAD).allow


def test_undefined_result_is_deny():
    d = client_with(lambda req: httpx.Response(200, json={})).decide_tool(PAYLOAD)
    assert not d.allow and d.reasons == ("opa_undefined_result",)


def test_non_boolean_allow_is_deny():
    for bogus in ("true", 1, "yes", None, [True]):
        c = client_with(lambda req, b=bogus: httpx.Response(200, json={"result": {"allow": b}}))
        assert not c.decide_tool(PAYLOAD).allow


def test_invalid_json_is_deny():
    assert not client_with(lambda req: httpx.Response(200, text="<html>")).decide_tool(PAYLOAD).allow


def test_allowed_ids_fail_closed():
    def boom(req):
        raise httpx.ConnectError("refused")

    assert client_with(boom).allowed_ids({}, "read", [{"id": "INV-1"}]) == set()
    assert client_with(lambda req: httpx.Response(200, json={})).allowed_ids({}, "read", [{"id": "INV-1"}]) == set()


def test_service_token_is_sent_and_input_wrapped():
    seen = {}

    def handler(req: httpx.Request):
        seen["auth"] = req.headers.get("authorization")
        seen["path"] = req.url.path
        seen["body"] = req.read()
        return httpx.Response(200, json={"result": {"allow": True}})

    client_with(handler).decide_tool(PAYLOAD)
    assert seen["auth"] == f"Bearer {SETTINGS.opa_token}"
    assert seen["path"] == "/v1/data/enterprise/tools/decision"
    assert b'"input"' in seen["body"]
