import { Badge, Card, ErrorBox, Loading } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export default function Roles() {
  const roles = useApi(() => api.roles(), []);
  const perms = useApi(() => api.permissions(), []);
  const all = perms.data?.permissions || [];
  return (
    <>
      <h1>Roles &amp; permissions</h1>
      <Card title="Role → permission matrix">
        {(roles.loading || perms.loading) && <Loading />}
        <ErrorBox error={roles.error || perms.error} />
        {roles.data && (
          <div className="table-wrap">
            <table className="matrix">
              <thead>
                <tr>
                  <th>Permission</th>
                  {roles.data.roles.map((r) => <th key={r.id}>{r.name}</th>)}
                </tr>
              </thead>
              <tbody>
                {all.map((p) => (
                  <tr key={p.id}>
                    <td><code>{p.name}</code></td>
                    {roles.data.roles.map((r) => (
                      <td key={r.id}>{r.permissions.includes(p.name) ? <Badge kind="ok">✓</Badge> : <span className="muted">–</span>}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted small">
          Read-only by design: roles are assigned in Keycloak and the role→permission mapping lives in the policy data
          (<code>opa/policies/data.json</code>) so it is code-reviewed. The ABAC rules (tenant, department, ownership,
          classification, limits, status) are in the Rego policies, not in this table.
        </p>
      </Card>
    </>
  );
}
