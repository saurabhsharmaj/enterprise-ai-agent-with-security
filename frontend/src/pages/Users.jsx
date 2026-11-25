import { useState } from "react";
import { Badge, Card, ErrorBox, Loading, Table, money } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export default function Users() {
  const { data, error, loading, reload } = useApi(() => api.users(), []);
  const [err, setErr] = useState(null);

  async function toggle(u) {
    setErr(null);
    try {
      await api.updateUser(u.id, { is_active: !u.is_active });
      reload();
    } catch (e) {
      setErr(e);
    }
  }
  async function setLimit(u) {
    const v = window.prompt(`New approval limit for ${u.username}`, String(u.approval_limit));
    if (v === null) return;
    setErr(null);
    try {
      await api.updateUser(u.id, { approval_limit: v });
      reload();
    } catch (e) {
      setErr(e);
    }
  }

  return (
    <>
      <h1>Users</h1>
      <Card title="Users in your tenant">
        {loading && <Loading />}
        <ErrorBox error={error} />
        <ErrorBox error={err} />
        <Table
          rows={data?.users}
          columns={[
            { key: "username", label: "Username" },
            { key: "full_name", label: "Name" },
            { key: "department", label: "Dept" },
            { key: "roles", label: "Roles", render: (u) => u.roles.map((r) => <Badge key={r} kind="info">{r}</Badge>) },
            { key: "approval_limit", label: "Approval limit", render: (u) => money(u.approval_limit) },
            { key: "is_active", label: "Status", render: (u) => (u.is_active ? <Badge kind="ok">active</Badge> : <Badge kind="bad">disabled</Badge>) },
            {
              key: "act",
              label: "",
              render: (u) => (
                <>
                  <button className="btn btn-small" onClick={() => toggle(u)}>{u.is_active ? "Disable" : "Enable"}</button>{" "}
                  <button className="btn btn-small" onClick={() => setLimit(u)}>Set limit</button>
                </>
              ),
            },
          ]}
        />
        <p className="muted small">
          Identity data (passwords, MFA, role assignment) is owned by Keycloak. This view holds only business attributes
          such as department and approval limit. Only users of your own tenant are visible.
        </p>
      </Card>
    </>
  );
}
