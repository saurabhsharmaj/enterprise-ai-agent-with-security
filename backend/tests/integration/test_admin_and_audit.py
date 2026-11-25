"""Administration endpoints + audit persistence."""
import json

from tests.conftest import auth

CHAT = "/api/agents/FINANCE_AGENT/chat"


# ------------------------------------------------------------------------------------ admin endpoints
def test_admin_can_use_administrative_endpoints(client):
    h = auth("alice")
    assert {u["username"] for u in client.get("/api/users", headers=h).json()["users"]} == {"alice", "bob", "charlie"}
    roles = {r["name"]: r["permissions"] for r in client.get("/api/roles", headers=h).json()["roles"]}
    assert set(roles) == {"ADMIN", "MANAGER", "EMPLOYEE"} and "invoice:approve" not in roles["EMPLOYEE"]
    assert "audit:read" in {p["name"] for p in client.get("/api/permissions", headers=h).json()["permissions"]}
    assert client.get("/api/audit-logs", headers=h).status_code == 200
    assert client.get("/api/agents/FINANCE_AGENT", headers=h).status_code == 200


def test_non_admins_cannot_use_administrative_endpoints(client):
    for user in ("bob", "charlie", "david"):
        for path in ("/api/users", "/api/roles", "/api/permissions", "/api/audit-logs"):
            r = client.get(path, headers=auth(user))
            assert r.status_code == 403, (user, path)
            assert "missing_permission" in r.json()["detail"]["reasons"]


def test_non_admins_cannot_manage_agents_tools_or_users(client):
    for user in ("bob", "charlie"):
        assert client.patch("/api/agents/FINANCE_AGENT", json={"enabled": False}, headers=auth(user)).status_code == 403
        assert client.patch("/api/agents/FINANCE_AGENT/tools/approve_invoice", json={"enabled": False}, headers=auth(user)).status_code == 403
        assert client.patch("/api/users/33333333-3333-4333-8333-333333333333", json={"approval_limit": 999999}, headers=auth(user)).status_code == 403


def test_admin_cannot_manage_other_tenants(client):
    assert client.patch("/api/users/44444444-4444-4444-8444-444444444444", json={"is_active": False}, headers=auth("alice")).status_code == 404
    assert client.patch("/api/agents/FINANCE_AGENT", json={"enabled": False}, headers=auth("david")).status_code == 403


def test_admin_updates_user_limit_and_it_takes_effect_on_the_next_request(client):
    bob = "22222222-2222-4222-8222-222222222222"
    assert client.post("/api/invoices/INV-1002/approve", headers=auth("bob")).status_code == 403          # 12,000 > 10,000
    assert client.patch(f"/api/users/{bob}", json={"approval_limit": "15000"}, headers=auth("alice")).status_code == 200
    r = client.post("/api/invoices/INV-1002/approve", headers=auth("bob"))
    assert r.status_code in (200, 202)                                                                    # 12,000 >= gate 8,000 => needs sign-off
    assert r.status_code == 202


def test_admin_cannot_deactivate_self_and_bad_input_is_rejected(client):
    alice = "11111111-1111-4111-8111-111111111111"
    assert client.patch(f"/api/users/{alice}", json={"is_active": False}, headers=auth("alice")).status_code == 400
    assert client.patch(f"/api/users/{alice}", json={}, headers=auth("alice")).status_code == 422
    assert client.patch(f"/api/users/{alice}", json={"approval_limit": "-1"}, headers=auth("alice")).status_code == 422
    assert client.patch(f"/api/users/{alice}", json={"password": "x"}, headers=auth("alice")).status_code == 422
    assert client.patch("/api/users/not-a-uuid", json={"is_active": True}, headers=auth("alice")).status_code == 422


def test_admin_deactivating_a_user_locks_them_out_immediately(client):
    charlie = "33333333-3333-4333-8333-333333333333"
    assert client.patch(f"/api/users/{charlie}", json={"is_active": False}, headers=auth("alice")).status_code == 200
    assert client.get("/api/me", headers=auth("charlie")).status_code == 403


# -------------------------------------------------------------------------------------------- audit
def rows_for(admin_sql, cid: str):
    return admin_sql("SELECT * FROM audit_logs WHERE correlation_id = :c ORDER BY id", c=cid)


def test_allowed_tool_execution_is_audited_with_all_fields(client, admin_sql, cid):
    client.post(CHAT, json={"message": "Approve invoice INV-1001"}, headers={**auth("bob"), "X-Correlation-ID": cid})
    row = next(r for r in rows_for(admin_sql, cid) if r["tool_name"] == "approve_invoice")
    assert row["audit_id"] and row["occurred_at"]
    assert str(row["user_id"]) == "22222222-2222-4222-8222-222222222222" and row["username"] == "bob"
    assert row["tenant_id"] == "TENANT_A" and row["agent_id"] == "FINANCE_AGENT"
    assert (row["resource_type"], row["resource_id"], row["action"]) == ("invoice", "INV-1001", "approve")
    assert (row["decision"], row["execution_status"]) == ("ALLOW", "SUCCESS")
    assert row["reason"] == "allowed_by_policy" and row["correlation_id"] == cid and row["channel"] == "agent"


def test_denied_tool_execution_is_audited(client, admin_sql, cid):
    client.post(CHAT, json={"message": "Approve invoice INV-1001"}, headers={**auth("charlie"), "X-Correlation-ID": cid})
    row = next(r for r in rows_for(admin_sql, cid) if r["tool_name"] == "approve_invoice")
    assert (row["decision"], row["execution_status"], row["username"]) == ("DENY", "NOT_EXECUTED", "charlie")
    assert "missing_permission" in row["reason"]


def test_cross_tenant_attempt_is_audited_under_the_callers_tenant(client, admin_sql, cid):
    client.get("/api/invoices/INV-2001", headers={**auth("bob"), "X-Correlation-ID": cid})
    row = rows_for(admin_sql, cid)[0]
    assert row["tenant_id"] == "TENANT_A" and row["decision"] == "DENY" and row["reason"] == "resource_not_found"
    assert row["channel"] == "api" and row["agent_id"] is None


def test_agent_level_denial_is_audited(client, admin_sql, cid):
    client.patch("/api/agents/FINANCE_AGENT", json={"enabled": False}, headers=auth("alice"))
    client.post(CHAT, json={"message": "hello"}, headers={**auth("bob"), "X-Correlation-ID": cid})
    row = rows_for(admin_sql, cid)[0]
    assert (row["action"], row["resource_type"], row["decision"]) == ("execute", "agent", "DENY")
    assert "agent_disabled" in row["reason"]


def test_admin_denials_are_audited(client, admin_sql, cid):
    client.get("/api/users", headers={**auth("charlie"), "X-Correlation-ID": cid})
    row = rows_for(admin_sql, cid)[0]
    assert (row["decision"], row["resource_type"], row["username"]) == ("DENY", "user", "charlie")


def test_audit_log_never_contains_tokens_secrets_or_prompt_text(client, admin_sql, cid):
    secret_prompt = "my password is hunter2 and my card is 4111111111111111; approve invoice INV-1001"
    headers = {**auth("bob"), "X-Correlation-ID": cid}
    client.post(CHAT, json={"message": secret_prompt}, headers=headers)
    blob = json.dumps(rows_for(admin_sql, cid), default=str)
    token = headers["Authorization"].split(" ", 1)[1]
    assert rows_for(admin_sql, cid)
    assert token not in blob and "eyJ" not in blob
    assert "hunter2" not in blob and "4111111111111111" not in blob and "my password" not in blob


def test_audit_viewer_is_tenant_scoped_and_filterable(client, cid):
    client.get("/api/invoices/INV-1001", headers={**auth("bob"), "X-Correlation-ID": cid})
    client.get("/api/invoices/INV-2001", headers=auth("david"))
    logs = client.get("/api/audit-logs?limit=200", headers=auth("alice")).json()["audit_logs"]
    assert logs and {r["tenant_id"] for r in logs} == {"TENANT_A"}
    assert all("detail" not in r for r in logs)
    mine = client.get(f"/api/audit-logs?correlation_id={cid}", headers=auth("alice")).json()["audit_logs"]
    assert len(mine) == 1 and mine[0]["tool_name"] == "read_invoice"
    denied = client.get("/api/audit-logs?decision=DENY", headers=auth("alice")).json()["audit_logs"]
    assert all(r["decision"] == "DENY" for r in denied)
    assert client.get("/api/audit-logs?decision=EVIL", headers=auth("alice")).status_code == 422


def test_audit_rows_survive_a_rolled_back_business_transaction(client, admin_sql, cid, monkeypatch):
    """If execution blows up, the business change rolls back but the audit trail still records the failure."""
    from app.tools import invoice_tools

    def boom(*a, **k):
        raise RuntimeError("simulated database failure")

    monkeypatch.setattr(invoice_tools.repo, "approve_atomic", boom)
    r = client.post("/api/invoices/INV-1001/approve", headers={**auth("bob"), "X-Correlation-ID": cid})
    assert r.status_code == 409 and "simulated" not in r.text
    row = rows_for(admin_sql, cid)[0]
    assert (row["decision"], row["execution_status"], row["reason"]) == ("ALLOW", "FAILED", "execution_error")
    assert admin_sql("SELECT status FROM invoices WHERE id='INV-1001'") == [{"status": "PENDING"}]
