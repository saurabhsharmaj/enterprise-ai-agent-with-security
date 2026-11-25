"""Idempotent seed data for the demo. Runs as the database OWNER (DATABASE_ADMIN_URL).

    python -m app.seed            # create missing rows, leave existing rows alone
    python -m app.seed --reset    # also restore demo invoices/POs to their initial state

Roles and permissions are generated from the OPA policy data (opa/policies/data.json), the single
source of truth, so the admin screens and the policy can never disagree.

User ids are the Keycloak `sub` values fixed in keycloak/build_realm.py. NO passwords here.
"""
import json
import os
import sys

from sqlalchemy import create_engine, text

TENANTS = [("TENANT_A", "Acme Corp (Tenant A)"), ("TENANT_B", "Globex Ltd (Tenant B)")]

# id, tenant, username, email, full name, department, approval_limit, role
USERS = [
    ("11111111-1111-4111-8111-111111111111", "TENANT_A", "alice", "alice@tenant-a.example", "Alice Anderson", "IT", 100000, "ADMIN"),
    ("22222222-2222-4222-8222-222222222222", "TENANT_A", "bob", "bob@tenant-a.example", "Bob Brown", "FINANCE", 10000, "MANAGER"),
    ("33333333-3333-4333-8333-333333333333", "TENANT_A", "charlie", "charlie@tenant-a.example", "Charlie Clark", "FINANCE", 0, "EMPLOYEE"),
    ("44444444-4444-4444-8444-444444444444", "TENANT_B", "david", "david@tenant-b.example", "David Davis", "FINANCE", 5000, "MANAGER"),
    # Data-owner only: has no Keycloak account, so it cannot log in. Owns Tenant B sample invoices.
    ("55555555-5555-4555-8555-555555555555", "TENANT_B", "erin", "erin@tenant-b.example", "Erin Evans", "FINANCE", 0, "EMPLOYEE"),
]

U = {u[2]: u[0] for u in USERS}

AGENT_TOOLS = {
    "search_invoices": "Search invoices visible to the caller",
    "read_invoice": "Read a single invoice by id",
    "create_purchase_order": "Create a purchase order (within the caller's approval limit)",
    "approve_invoice": "Approve a pending invoice (within the caller's approval limit)",
    "search_documents": "Search documents visible to the caller",
}

# id, tenant, vendor, description, amount, status, department, classification, owner, approved_by
INVOICES = [
    ("INV-1001", "TENANT_A", "Office Supplies Co", "Quarterly stationery", 4500, "PENDING", "FINANCE", "INTERNAL", "charlie", None),
    ("INV-1002", "TENANT_A", "CloudHost Inc", "Annual hosting (above Bob's limit)", 12000, "PENDING", "FINANCE", "INTERNAL", "charlie", None),
    ("INV-1003", "TENANT_A", "Print Partners", "Marketing collateral (needs human sign-off)", 9000, "PENDING", "FINANCE", "INTERNAL", "charlie", None),
    ("INV-1004", "TENANT_A", "Legal Eagles LLP", "Retainer (already approved)", 3000, "APPROVED", "FINANCE", "INTERNAL", "charlie", "bob"),
    ("INV-1005", "TENANT_A", "Audit Partners", "Confidential audit fee", 7000, "PENDING", "FINANCE", "CONFIDENTIAL", "bob", None),
    ("INV-1006", "TENANT_A", "Datacenter Ltd", "IT rack rental", 2500, "PENDING", "IT", "INTERNAL", "alice", None),
    ("INV-1007", "TENANT_A", "Coffee Roasters", "Pantry supplies", 800, "PENDING", "FINANCE", "INTERNAL", "charlie", None),
    ("INV-2001", "TENANT_B", "Globex Supplier", "Tenant B steel order", 3000, "PENDING", "FINANCE", "INTERNAL", "erin", None),
    ("INV-2002", "TENANT_B", "Globex Freight", "Tenant B freight (above David's limit)", 7000, "PENDING", "FINANCE", "INTERNAL", "erin", None),
]

DOCUMENTS = [
    ("TENANT_A", "Travel Expense Policy", "Employees must file expenses within 30 days.", "FINANCE", "INTERNAL", "bob"),
    ("TENANT_A", "Invoice Approval Procedure", "Managers approve within their limit; larger amounts need an admin.", "FINANCE", "INTERNAL", "bob"),
    ("TENANT_A", "Q3 Budget Forecast", "Confidential budget forecast for the finance team.", "FINANCE", "CONFIDENTIAL", "bob"),
    ("TENANT_A", "IT Security Runbook", "Incident response steps for the IT department.", "IT", "INTERNAL", "alice"),
    ("TENANT_B", "Globex Procurement Policy", "Tenant B procurement rules. Invoice handling.", "FINANCE", "INTERNAL", "erin"),
]

TENANT_AGENTS = [("FINANCE_AGENT", "Finance Agent", "Searches and reads invoices, creates purchase orders, approves invoices.")]


def main(reset: bool) -> None:
    url = os.environ.get("DATABASE_ADMIN_URL")
    if not url:
        sys.exit("DATABASE_ADMIN_URL is required")
    data_file = os.environ.get("OPA_DATA_FILE", "/opa/policies/data.json")
    with open(data_file, encoding="utf-8") as fh:
        policy_data = json.load(fh)

    engine = create_engine(url)
    with engine.begin() as c:
        for tid, name in TENANTS:
            c.execute(text("INSERT INTO tenants (id, name) VALUES (:i, :n) "
                           "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name"), {"i": tid, "n": name})

        # roles + permissions + role_permissions straight from the policy data
        all_perms = sorted({p for r in policy_data["roles"].values() for p in r["permissions"]})
        for perm in all_perms:
            c.execute(text("INSERT INTO permissions (name, description) VALUES (:n, :d) ON CONFLICT (name) DO NOTHING"),
                      {"n": perm, "d": f"Allows {perm.split(':')[1]} on {perm.split(':')[0]}"})
        for role, spec in policy_data["roles"].items():
            c.execute(text("INSERT INTO roles (name, description) VALUES (:n, :d) ON CONFLICT (name) DO NOTHING"),
                      {"n": role, "d": f"{role.title()} role"})
            c.execute(text("DELETE FROM role_permissions WHERE role_id = (SELECT id FROM roles WHERE name = :r)"), {"r": role})
            for perm in spec["permissions"]:
                c.execute(text("INSERT INTO role_permissions (role_id, permission_id) "
                               "SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = :r AND p.name = :p"),
                          {"r": role, "p": perm})

        for uid, tenant, uname, email, full, dept, limit, role in USERS:
            c.execute(text(
                "INSERT INTO users (id, tenant_id, username, email, full_name, department, approval_limit) "
                "VALUES (:id, :t, :u, :e, :f, :d, :l) ON CONFLICT (id) DO UPDATE SET "
                "department = EXCLUDED.department, approval_limit = EXCLUDED.approval_limit, "
                "full_name = EXCLUDED.full_name, email = EXCLUDED.email"),
                {"id": uid, "t": tenant, "u": uname, "e": email, "f": full, "d": dept, "l": limit})
            c.execute(text("DELETE FROM user_roles WHERE user_id = :u"), {"u": uid})
            c.execute(text("INSERT INTO user_roles (user_id, role_id) SELECT :u, id FROM roles WHERE name = :r"),
                      {"u": uid, "r": role})

        for tid, _ in TENANTS:
            for aid, aname, adesc in TENANT_AGENTS:
                c.execute(text("INSERT INTO agents (id, tenant_id, name, description) VALUES (:i, :t, :n, :d) "
                               "ON CONFLICT (tenant_id, id) DO NOTHING"), {"i": aid, "t": tid, "n": aname, "d": adesc})
                for tool, desc in AGENT_TOOLS.items():
                    c.execute(text("INSERT INTO agent_tools (tenant_id, agent_id, tool_name, description) "
                                   "VALUES (:t, :a, :n, :d) ON CONFLICT DO NOTHING"),
                              {"t": tid, "a": aid, "n": tool, "d": desc})

        for inv in INVOICES:
            iid, tenant, vendor, desc, amount, status, dept, cls, owner, approver = inv
            params = {"i": iid, "t": tenant, "v": vendor, "d": desc, "a": amount, "s": status, "dp": dept,
                      "c": cls, "o": U[owner], "ab": U[approver] if approver else None}
            if reset:
                c.execute(text("DELETE FROM invoices WHERE tenant_id = :t AND id = :i"), params)
            c.execute(text(
                "INSERT INTO invoices (id, tenant_id, vendor, description, amount, status, department, "
                "classification, owner_id, approved_by, approved_at) "
                "VALUES (:i, :t, :v, :d, :a, :s, :dp, :c, :o, :ab, "
                "CASE WHEN CAST(:ab AS uuid) IS NULL THEN NULL ELSE now() END) "
                "ON CONFLICT (tenant_id, id) DO NOTHING"), params)

        if reset:
            c.execute(text("DELETE FROM approval_requests"))
            c.execute(text("DELETE FROM purchase_orders"))
            c.execute(text("UPDATE agents SET enabled = true"))
            c.execute(text("UPDATE agent_tools SET enabled = true, requires_approval = false"))
            c.execute(text("UPDATE users SET is_active = true"))
        for tenant, title, body, dept, cls, owner in DOCUMENTS:
            c.execute(text("INSERT INTO documents (tenant_id, title, body, department, classification, owner_id) "
                           "SELECT CAST(:t AS varchar), CAST(:ti AS varchar), :b, :d, :c, CAST(:o AS uuid) WHERE NOT EXISTS "
                           "(SELECT 1 FROM documents WHERE tenant_id = CAST(:t AS varchar) AND title = CAST(:ti AS varchar))"),
                      {"t": tenant, "ti": title, "b": body, "d": dept, "c": cls, "o": U[owner]})
    print("seed complete" + (" (reset)" if reset else ""))


if __name__ == "__main__":
    main("--reset" in sys.argv)
