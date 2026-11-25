"""End-to-end authorisation over HTTP: real JWT validation -> real PostgreSQL -> real OPA."""
from tests.conftest import auth, make_token


def status_of(admin_sql, invoice_id: str, tenant: str = "TENANT_A") -> str:
    return admin_sql("SELECT status FROM invoices WHERE tenant_id = :t AND id = :i", t=tenant, i=invoice_id)[0]["status"]


# ------------------------------------------------------------------------------- authentication
def test_valid_jwt_is_accepted_and_context_comes_from_token_and_db(client):
    r = client.get("/api/me", headers=auth("bob"))
    assert r.status_code == 200
    me = r.json()
    assert (me["username"], me["tenant_id"], me["roles"], me["department"]) == ("bob", "TENANT_A", ["MANAGER"], "FINANCE")
    assert me["approval_limit"] == 10000                      # from the database, not from the token
    assert "invoice:approve" in me["permissions"]


def test_identity_supplied_by_the_frontend_is_ignored(client):
    r = client.get("/api/me?tenant_id=TENANT_B&role=ADMIN&user=alice",
                   headers={**auth("charlie"), "X-Tenant-Id": "TENANT_B", "X-User-Id": "alice", "X-Roles": "ADMIN"})
    me = r.json()
    assert (me["username"], me["tenant_id"], me["roles"]) == ("charlie", "TENANT_A", ["EMPLOYEE"])


def test_valid_token_for_unprovisioned_user_is_rejected(client):
    r = client.get("/api/me", headers={"Authorization": "Bearer " + make_token(
        "bob", sub="99999999-9999-4999-8999-999999999999")})
    assert r.status_code == 403 and r.json()["detail"]["error"] == "user_not_provisioned"


def test_token_claiming_another_tenant_cannot_see_the_user(client):
    """Bob's real id but a forged-looking tenant claim (validly signed): RLS + tenant filter find no user."""
    r = client.get("/api/me", headers={"Authorization": "Bearer " + make_token("bob", tenant_id="TENANT_B")})
    assert r.status_code == 403


def test_deactivated_user_is_blocked_even_with_a_valid_token(client, admin_sql):
    admin_sql("UPDATE users SET is_active = false WHERE username = 'charlie'")
    r = client.get("/api/me", headers=auth("charlie"))
    assert r.status_code == 403 and r.json()["detail"]["error"] == "user_disabled"


# ------------------------------------------------------------------------------------ reading
def test_manager_can_read_invoices(client):
    assert client.get("/api/invoices/INV-1001", headers=auth("bob")).status_code == 200
    ids = {i["id"] for i in client.get("/api/invoices", headers=auth("bob")).json()["data"]["invoices"]}
    assert {"INV-1001", "INV-1002", "INV-1005"} <= ids
    assert "INV-1006" not in ids                                # IT department invoice
    assert not any(i.startswith("INV-2") for i in ids)          # other tenant


def test_employee_sees_only_permitted_invoices(client):
    ids = {i["id"] for i in client.get("/api/invoices", headers=auth("charlie")).json()["data"]["invoices"]}
    assert "INV-1001" in ids
    assert "INV-1005" not in ids                                # CONFIDENTIAL
    assert "INV-1006" not in ids                                # IT department


def test_employee_cannot_read_a_confidential_invoice_directly(client):
    r = client.get("/api/invoices/INV-1005", headers=auth("charlie"))
    assert r.status_code == 403 and "insufficient_clearance" in r.json()["detail"]["reasons"]


def test_admin_reads_any_department_in_own_tenant(client):
    assert client.get("/api/invoices/INV-1005", headers=auth("alice")).status_code == 200
    assert client.get("/api/invoices/INV-1006", headers=auth("alice")).status_code == 200


def test_invalid_invoice_id_is_rejected_at_the_edge(client):
    assert client.get("/api/invoices/INV-1;DROP", headers=auth("bob")).status_code == 422


# ------------------------------------------------------------------------------------ approving
def test_employee_cannot_approve_invoices(client, admin_sql):
    r = client.post("/api/invoices/INV-1001/approve", headers=auth("charlie"))
    assert r.status_code == 403
    assert "missing_permission" in r.json()["detail"]["reasons"]
    assert status_of(admin_sql, "INV-1001") == "PENDING"


def test_manager_approves_within_limit(client, admin_sql):
    r = client.post("/api/invoices/INV-1001/approve", headers=auth("bob"))
    assert r.status_code == 200 and r.json()["data"]["status"] == "APPROVED"
    row = admin_sql("SELECT status, approved_by FROM invoices WHERE tenant_id='TENANT_A' AND id='INV-1001'")[0]
    assert row["status"] == "APPROVED" and str(row["approved_by"]) == "22222222-2222-4222-8222-222222222222"


def test_manager_cannot_approve_above_limit(client, admin_sql):
    r = client.post("/api/invoices/INV-1002/approve", headers=auth("bob"))       # 12,000 > 10,000
    assert r.status_code == 403 and "approval_limit_exceeded" in r.json()["detail"]["reasons"]
    assert status_of(admin_sql, "INV-1002") == "PENDING"


def test_limits_are_per_user(client):
    assert "approval_limit_exceeded" in client.post("/api/invoices/INV-2002/approve", headers=auth("david")).json()["detail"]["reasons"]   # 7,000 > 5,000
    assert client.post("/api/invoices/INV-2001/approve", headers=auth("david")).status_code == 200                                         # 3,000


def test_invoice_cannot_be_approved_twice(client):
    assert client.post("/api/invoices/INV-1001/approve", headers=auth("bob")).status_code == 200
    again = client.post("/api/invoices/INV-1001/approve", headers=auth("bob"))
    assert again.status_code == 403 and "invoice_not_pending" in again.json()["detail"]["reasons"]
    assert client.post("/api/invoices/INV-1004/approve", headers=auth("alice")).status_code == 403   # seeded as already APPROVED


def test_nobody_approves_their_own_invoice(client):
    r = client.post("/api/invoices/INV-1005/approve", headers=auth("bob"))          # Bob owns INV-1005
    assert r.status_code == 403 and "self_approval_forbidden" in r.json()["detail"]["reasons"]


def test_admin_may_approve_above_manager_limit(client):
    assert client.post("/api/invoices/INV-1002/approve", headers=auth("alice")).status_code == 200


# --------------------------------------------------------------------------------- purchase orders
def test_manager_creates_purchase_order_within_limit(client):
    r = client.post("/api/purchase-orders", json={"amount": "5000", "vendor": "Acme"}, headers=auth("bob"))
    assert r.status_code == 201 and r.json()["data"]["purchase_order"]["po_number"].startswith("PO-")


def test_purchase_order_limits_and_roles(client):
    assert client.post("/api/purchase-orders", json={"amount": "10000.01"}, headers=auth("bob")).status_code == 403
    assert client.post("/api/purchase-orders", json={"amount": "5001"}, headers=auth("david")).status_code == 403
    assert client.post("/api/purchase-orders", json={"amount": "5000"}, headers=auth("david")).status_code == 201
    assert client.post("/api/purchase-orders", json={"amount": "10"}, headers=auth("charlie")).status_code == 403


def test_purchase_order_body_cannot_choose_tenant_or_owner(client):
    for extra in ({"tenant_id": "TENANT_B"}, {"department": "IT"}, {"created_by": "x"}, {"approval_limit": 999999}):
        r = client.post("/api/purchase-orders", json={"amount": "10", **extra}, headers=auth("bob"))
        assert r.status_code == 422, extra


def test_purchase_order_is_created_in_callers_tenant_and_department(client, admin_sql):
    client.post("/api/purchase-orders", json={"amount": "100"}, headers=auth("david"))
    row = admin_sql("SELECT tenant_id, department FROM purchase_orders")[0]
    assert (row["tenant_id"], row["department"]) == ("TENANT_B", "FINANCE")


# ---------------------------------------------------------------------------- authorization check
def test_authorization_check_reports_my_own_permissions(client):
    body = {"action": "approve", "resource_type": "invoice", "resource_id": "INV-1001"}
    assert client.post("/api/authorization/check", json=body, headers=auth("bob")).json()["allowed"] is True
    denied = client.post("/api/authorization/check", json=body, headers=auth("charlie")).json()
    assert denied["allowed"] is False and "missing_permission" in denied["reasons"]


def test_authorization_check_is_not_an_opa_proxy(client):
    for extra in ({"subject": {"roles": ["ADMIN"]}}, {"tenant_id": "TENANT_B"}, {"input": {}}):
        r = client.post("/api/authorization/check", json={"action": "read", "resource_type": "invoice", **extra},
                        headers=auth("charlie"))
        assert r.status_code == 422
    r = client.post("/api/authorization/check", json={"action": "read", "resource_type": "invoice", "resource_id": "INV-2001"},
                    headers=auth("bob"))
    assert r.json() == {**r.json(), "allowed": False, "reasons": ["resource_not_found"]}


def test_rate_limit_on_sensitive_endpoint(client):
    codes = [client.post("/api/invoices/INV-1004/approve", headers=auth("bob")).status_code for _ in range(22)]
    assert codes[-1] == 429 and 429 not in codes[:20]
