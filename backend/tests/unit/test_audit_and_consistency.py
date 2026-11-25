"""Audit sanitisation + cross-component consistency (Keycloak realm <-> seed <-> OPA data <-> tool registry)."""
import json
import pathlib
import re

import pytest

from app import seed
from app.audit.service import sanitize_detail
from app.tools.registry import REGISTRY
from tests.conftest import USERS

import os

import app as app_pkg

HERE = pathlib.Path(__file__).resolve()
_ROOTS = [HERE.parents[3], pathlib.Path("/")]          # repo checkout, or the test container layout


def _find(*relative: str) -> pathlib.Path | None:
    candidates = []
    if relative[-1] == "data.json" and os.environ.get("OPA_DATA_FILE"):
        candidates.append(pathlib.Path(os.environ["OPA_DATA_FILE"]))
    candidates += [root.joinpath(*relative) for root in _ROOTS]
    return next((c for c in candidates if c.exists()), None)


DATA_JSON = _find("opa", "policies", "data.json")
REALM_JSON = _find("keycloak", "realm-export.json")


def test_secrets_are_stripped_from_audit_detail():
    clean = sanitize_detail({"access_token": "eyJ...", "Authorization": "Bearer x", "password": "p", "client_secret": "s",
                             "api_key": "k", "approval_request_id": "abc", "fields": "amount"})
    assert clean == {"approval_request_id": "abc", "fields": "amount"}


def test_nested_and_oversized_detail_is_dropped_or_truncated():
    clean = sanitize_detail({"obj": {"a": 1}, "list": [1, 2], "long": "x" * 5000})
    assert "obj" not in clean and "list" not in clean
    assert len(clean["long"]) == 200


def test_seed_user_ids_match_test_tokens():
    seeded = {u[2]: u for u in seed.USERS}
    for name, u in USERS.items():
        assert seeded[name][0] == u["id"]
        assert seeded[name][1] == u["tenant"]
        assert seeded[name][5] == u["dept"]
        assert seeded[name][7] == u["roles"][0]


def test_seed_matches_required_limits():
    limits = {u[2]: u[6] for u in seed.USERS}
    assert limits["bob"] == 10000 and limits["david"] == 5000


def test_realm_export_matches_seed():
    if REALM_JSON is None:
        pytest.skip("realm-export.json not available in this environment")
    realm = json.loads(REALM_JSON.read_text())
    assert realm["realm"] == "enterprise-ai"
    by_name = {u["username"]: u for u in realm["users"]}
    for name, u in USERS.items():
        kc = by_name[name]
        assert kc["id"] == u["id"]
        assert kc["attributes"]["tenant_id"] == [u["tenant"]]
        assert kc["realmRoles"] == u["roles"]
        assert "password" not in json.dumps(kc.get("attributes", {})).lower()
    frontend = next(c for c in realm["clients"] if c["clientId"] == "enterprise-ai-frontend")
    assert frontend["publicClient"] and frontend["standardFlowEnabled"]
    assert not frontend["implicitFlowEnabled"] and not frontend["directAccessGrantsEnabled"]
    assert frontend["attributes"]["pkce.code.challenge.method"] == "S256"
    claim_names = {m["name"] for m in frontend["protocolMappers"]}
    assert {"tenant_id", "roles", "groups", "api-audience", "department"} <= claim_names


def test_every_registered_tool_is_in_the_opa_catalogue():
    assert DATA_JSON is not None, "OPA data.json not found"
    data = json.loads(DATA_JSON.read_text())
    assert set(REGISTRY) == set(data["tools"]) == set(data["agent_tools"]["FINANCE_AGENT"]) == set(seed.AGENT_TOOLS)
    for name, spec in REGISTRY.items():
        assert data["tools"][name] == {"resource_type": spec.resource_type, "action": spec.action}


def test_every_role_permission_in_opa_data_has_valid_format():
    assert DATA_JSON is not None, "OPA data.json not found"
    data = json.loads(DATA_JSON.read_text())
    for role, spec in data["roles"].items():
        assert all(re.match(r"^[a-z_]+:[a-z_]+$", p) for p in spec["permissions"]), role


def test_no_authorization_rules_hardcoded_in_application_code():
    """Guard-rail: application code must not branch on role names; only OPA decides."""
    offenders = []
    app_dir = pathlib.Path(app_pkg.__file__).parent
    for path in app_dir.rglob("*.py"):
        if path.name in {"seed.py", "jwt.py", "security.py"}:      # jwt/security only filter KNOWN role names / is_admin hint
            continue
        text = path.read_text()
        if re.search(r"""["'](ADMIN|MANAGER|EMPLOYEE)["']\s*(in|==)|(==|in)\s*["'](ADMIN|MANAGER|EMPLOYEE)["']""", text):
            offenders.append(str(path.relative_to(app_dir)))
    assert offenders == []
