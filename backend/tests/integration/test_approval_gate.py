"""Human approval gate for high-risk actions (INV-1003 = 9,000: within Bob's limit but >= the 8,000 gate)."""
from tests.conftest import auth

CHAT = "/api/agents/FINANCE_AGENT/chat"


def test_high_value_approval_is_parked_until_an_admin_decides(client, admin_sql):
    # 1. Bob (within his limit) asks via the REST API: no execution, an approval request is created.
    r = client.post("/api/invoices/INV-1003/approve", headers=auth("bob"))
    assert r.status_code == 202 and r.json()["status"] == "pending_approval"
    request_id = r.json()["approval_request_id"]
    assert admin_sql("SELECT status FROM invoices WHERE id='INV-1003'") == [{"status": "PENDING"}]

    # 2. Repeating the request does not spawn duplicates, and still does not execute.
    again = client.post("/api/invoices/INV-1003/approve", headers=auth("bob"))
    assert again.status_code == 202 and again.json()["approval_request_id"] == request_id
    assert admin_sql("SELECT count(*) AS n FROM approval_requests")[0]["n"] == 1

    # 3. The requester (a manager) cannot decide, nor can an employee.
    for user in ("bob", "charlie"):
        d = client.post(f"/api/approvals/{request_id}/decision", json={"decision": "APPROVE"}, headers=auth(user))
        assert d.status_code == 403, user

    # 4. Another tenant's admin cannot even see the request.
    assert client.post(f"/api/approvals/{request_id}/decision", json={"decision": "APPROVE"}, headers=auth("david")).status_code == 404

    # 5. Still not executed. The admin approves the REQUEST (not the invoice).
    assert admin_sql("SELECT status FROM invoices WHERE id='INV-1003'") == [{"status": "PENDING"}]
    d = client.post(f"/api/approvals/{request_id}/decision", json={"decision": "APPROVE"}, headers=auth("alice"))
    assert d.status_code == 200 and d.json()["status"] == "APPROVED"

    # 6. Bob repeats; OPA now sees an approval grant read from the database and the action executes once.
    done = client.post("/api/invoices/INV-1003/approve", headers=auth("bob"))
    assert done.status_code == 200 and done.json()["data"]["status"] == "APPROVED"
    assert admin_sql("SELECT status FROM approval_requests") == [{"status": "EXECUTED"}]

    # 7. The grant is single-use and the invoice cannot be approved twice.
    assert client.post("/api/invoices/INV-1003/approve", headers=auth("bob")).status_code == 403


def test_agent_path_hits_the_same_gate(client, admin_sql):
    r = client.post(CHAT, json={"message": "Approve invoice INV-1003"}, headers=auth("bob"))
    step = r.json()["steps"][0]
    assert step["status"] == "pending_approval" and step["approval_request_id"]
    assert "approval" in r.json()["reply"].lower()
    assert admin_sql("SELECT status FROM invoices WHERE id='INV-1003'") == [{"status": "PENDING"}]


def test_rejected_request_does_not_unlock_the_action(client, admin_sql):
    rid = client.post("/api/invoices/INV-1003/approve", headers=auth("bob")).json()["approval_request_id"]
    assert client.post(f"/api/approvals/{rid}/decision", json={"decision": "REJECT"}, headers=auth("alice")).status_code == 200
    r = client.post("/api/invoices/INV-1003/approve", headers=auth("bob"))
    assert r.status_code == 202 and r.json()["approval_request_id"] != rid        # a fresh request is needed
    assert admin_sql("SELECT status FROM invoices WHERE id='INV-1003'") == [{"status": "PENDING"}]


def test_expired_request_cannot_be_decided_or_used(client, admin_sql):
    rid = client.post("/api/invoices/INV-1003/approve", headers=auth("bob")).json()["approval_request_id"]
    admin_sql("UPDATE approval_requests SET expires_at = now() - interval '1 minute'")
    assert client.post(f"/api/approvals/{rid}/decision", json={"decision": "APPROVE"}, headers=auth("alice")).status_code == 409


def test_grant_is_bound_to_the_exact_arguments_and_requester(client, admin_sql):
    rid = client.post("/api/invoices/INV-1003/approve", headers=auth("bob")).json()["approval_request_id"]
    client.post(f"/api/approvals/{rid}/decision", json={"decision": "APPROVE"}, headers=auth("alice"))
    # A different manager-capable user (admin Alice is exempt anyway) cannot ride Bob's grant: Charlie is simply denied.
    assert client.post("/api/invoices/INV-1003/approve", headers=auth("charlie")).status_code == 403
    assert admin_sql("SELECT status FROM approval_requests") == [{"status": "APPROVED"}]       # not consumed by anyone else


def test_per_tool_flag_gates_even_small_amounts_and_the_rest_api_cannot_bypass_it(client, admin_sql):
    client.patch("/api/agents/FINANCE_AGENT/tools/approve_invoice", json={"requires_approval": True}, headers=auth("alice"))
    via_agent = client.post(CHAT, json={"message": "Approve invoice INV-1001"}, headers=auth("bob")).json()["steps"][0]
    via_rest = client.post("/api/invoices/INV-1001/approve", headers=auth("bob"))
    assert via_agent["status"] == "pending_approval" and via_rest.status_code == 202
    assert admin_sql("SELECT status FROM invoices WHERE id='INV-1001'") == [{"status": "PENDING"}]


def test_admin_is_exempt_from_the_gate(client):
    assert client.post("/api/invoices/INV-1003/approve", headers=auth("alice")).status_code == 200


def test_approvals_listing_scope(client):
    rid = client.post("/api/invoices/INV-1003/approve", headers=auth("bob")).json()["approval_request_id"]
    assert [a["id"] for a in client.get("/api/approvals", headers=auth("alice")).json()["approvals"]] == [rid]
    assert [a["id"] for a in client.get("/api/approvals", headers=auth("bob")).json()["approvals"]] == [rid]
    assert client.get("/api/approvals", headers=auth("charlie")).status_code == 403
    assert client.get("/api/approvals", headers=auth("david")).json()["approvals"] == []
