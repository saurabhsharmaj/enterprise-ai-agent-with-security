import { useAuth } from "../auth/AuthProvider";

const DEMO = [
  ["alice", "ADMIN", "IT", "TENANT_A", "Alice#Dev2026"],
  ["bob", "MANAGER", "FINANCE", "TENANT_A", "Bob#Dev2026"],
  ["charlie", "EMPLOYEE", "FINANCE", "TENANT_A", "Charlie#Dev2026"],
  ["david", "MANAGER", "FINANCE", "TENANT_B", "David#Dev2026"],
];

export default function Login({ error }) {
  const { login } = useAuth();
  return (
    <div className="login">
      <div className="login-card">
        <h1>Enterprise AI Agent Platform</h1>
        <p className="muted">
          Sign in with your corporate identity. Authentication is handled by Keycloak (OpenID Connect, Authorization Code
          Flow + PKCE). This app never sees your password.
        </p>
        {error && (
          <div className="alert alert-error" role="alert">
            Signed in, but the platform could not load your profile: {error.message}
          </div>
        )}
        <button className="btn btn-primary" onClick={login}>
          Sign in with Keycloak
        </button>
        <details className="demo">
          <summary>Development demo accounts</summary>
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Dept</th>
                <th>Tenant</th>
                <th>Password</th>
              </tr>
            </thead>
            <tbody>
              {DEMO.map((r) => (
                <tr key={r[0]}>
                  {r.map((c, i) => (
                    <td key={i}>{i === 4 ? <code>{c}</code> : c}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">Demo credentials for local development only.</p>
        </details>
      </div>
    </div>
  );
}
