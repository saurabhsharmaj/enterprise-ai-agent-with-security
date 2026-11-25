"""Tenant isolation at EVERY layer: API/service, OPA, and PostgreSQL row-level security."""
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.authorization.opa_client import OpaClient
from app.core.db import new_tenant_session
from tests.conftest import SETTINGS, auth


# ---------------------------------------------------------------------------------- service layer
@pytest.mark.parametrize("user,invoice", [("bob", "INV-2001"), ("alice", "INV-2001"), ("david", "INV-1001"), ("david", "INV-1005")])
def test_cross_tenant_read_is_denied_even_for_admins(client, user, invoice):
    r = client.get(f"/api/invoices/{invoice}", headers=auth(user))
    assert r.status_code == 404                                  # identical to "does not exist": no IDOR oracle
    assert r.json()["detail"]["reasons"] == ["resource_not_found"]


def test_cross_tenant_approve_is_denied_and_changes_nothing(client, admin_sql):
    assert client.post("/api/invoices/INV-2001/approve", headers=auth("alice")).status_code == 404
    assert client.post("/api/invoices/INV-1001/approve", headers=auth("david")).status_code == 404
    assert admin_sql("SELECT status FROM invoices WHERE id IN ('INV-2001','INV-1001')") == [{"status": "PENDING"}] * 2


def test_search_never_returns_other_tenants_rows(client):
    for user, forbidden in (("alice", "INV-2"), ("bob", "INV-2"), ("david", "INV-1")):
        ids = [i["id"] for i in client.get("/api/invoices?limit=50", headers=auth(user)).json()["data"]["invoices"]]
        assert ids and not any(i.startswith(forbidden) for i in ids), (user, ids)


def test_admin_listings_are_tenant_scoped(client):
    users_a = {u["username"] for u in client.get("/api/users", headers=auth("alice")).json()["users"]}
    assert users_a == {"alice", "bob", "charlie"}
    assert client.get("/api/users", headers=auth("david")).status_code == 403      # manager in tenant B


# ----------------------------------------------------------------------------- OPA is independent
def test_opa_denies_cross_tenant_even_if_the_data_layer_leaks(client, admin_sql, monkeypatch):
    """Simulate a bug that bypasses the tenant filter (repo returns Tenant B's invoice to Alice, the Tenant A admin).
    The OPA tenant rule must still stop the action, and nothing may change."""
    from app.tools import invoice_tools

    leaked = admin_sql("SELECT i.*, u.username AS owner_username FROM invoices i JOIN users u ON u.id = i.owner_id "
                       "WHERE i.id = 'INV-2001'")[0]
    monkeypatch.setattr(invoice_tools.repo, "get", lambda db, tenant, invoice_id: dict(leaked))

    r = client.post("/api/invoices/INV-2001/approve", headers=auth("alice"))
    assert r.status_code == 403 and "tenant_mismatch" in r.json()["detail"]["reasons"]
    assert client.get("/api/invoices/INV-2001", headers=auth("alice")).status_code == 403
    assert admin_sql("SELECT status FROM invoices WHERE id = 'INV-2001'") == [{"status": "PENDING"}]


def test_opa_tenant_rule_directly():
    opa = OpaClient(SETTINGS)
    subject = {"id": "11111111-1111-4111-8111-111111111111", "tenant_id": "TENANT_A", "roles": ["ADMIN"],
               "department": "IT", "approval_limit": 100000}
    res = {"type": "invoice", "id": "INV-2001", "tenant_id": "TENANT_B", "department": "FINANCE", "owner_id": "x",
           "status": "PENDING", "classification": "INTERNAL", "amount": 1}
    d = opa.decide_resource(subject, "read", res)
    assert not d.allow and "tenant_mismatch" in d.reasons


def test_opa_rest_api_is_not_reachable_without_the_service_token():
    import httpx

    assert httpx.post(f"{SETTINGS.opa_url}/v1/data/enterprise/authz/decision", json={"input": {}}).status_code == 401
    bad = httpx.post(f"{SETTINGS.opa_url}/v1/data/enterprise/authz/decision", json={"input": {}},
                     headers={"Authorization": "Bearer " + "z" * 48})
    assert bad.status_code == 401
    assert httpx.put(f"{SETTINGS.opa_url}/v1/policies/evil", content="package evil",
                     headers={"Authorization": f"Bearer {SETTINGS.opa_token}"}).status_code == 401
    assert httpx.get(f"{SETTINGS.opa_url}/v1/data", headers={"Authorization": f"Bearer {SETTINGS.opa_token}"}).status_code == 401


# ----------------------------------------------------------------------------- PostgreSQL RLS
def test_rls_hides_other_tenants_even_without_a_where_clause():
    s = new_tenant_session("TENANT_A")
    try:
        tenants = {r[0] for r in s.execute(text("SELECT DISTINCT tenant_id FROM invoices"))}
        users = {r[0] for r in s.execute(text("SELECT DISTINCT tenant_id FROM users"))}
        assert tenants == {"TENANT_A"} and users == {"TENANT_A"}
    finally:
        s.close()


def test_rls_without_a_tenant_returns_nothing():
    s = new_tenant_session("")
    try:
        for table in ("invoices", "users", "documents", "agents", "audit_logs", "approval_requests", "purchase_orders"):
            assert s.execute(text(f"SELECT count(*) FROM {table}")).scalar() == 0, table
    finally:
        s.close()


def test_rls_blocks_writing_into_another_tenant():
    s = new_tenant_session("TENANT_A")
    try:
        with pytest.raises(DBAPIError):
            s.execute(text("INSERT INTO purchase_orders (tenant_id, po_number, vendor, amount, department, created_by) "
                           "VALUES ('TENANT_B', 'PO-EVIL', 'x', 1, 'FINANCE', '11111111-1111-4111-8111-111111111111')"))
    finally:
        s.rollback()
        s.close()


def test_rls_blocks_updating_another_tenants_rows():
    s = new_tenant_session("TENANT_A")
    try:
        n = s.execute(text("UPDATE invoices SET status = 'REJECTED' WHERE tenant_id = 'TENANT_B'")).rowcount
        assert n == 0
    finally:
        s.rollback()
        s.close()


def test_runtime_role_cannot_change_or_delete_audit_logs_or_alter_schema():
    for stmt in ("UPDATE audit_logs SET decision = 'ALLOW'", "DELETE FROM audit_logs", "TRUNCATE audit_logs",
                 "CREATE TABLE evil (a int)", "DROP TABLE invoices", "ALTER TABLE users ADD COLUMN password text",
                 "UPDATE roles SET name = 'X'", "INSERT INTO role_permissions VALUES (1, 1)"):
        s = new_tenant_session("TENANT_A")
        try:
            with pytest.raises(DBAPIError):
                s.execute(text(stmt))
        finally:
            s.rollback()
            s.close()


def test_users_table_has_no_credential_columns(admin_sql):
    cols = {r["column_name"] for r in admin_sql(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'")}
    assert not {c for c in cols if "pass" in c or "secret" in c or "credential" in c or "hash" in c}
