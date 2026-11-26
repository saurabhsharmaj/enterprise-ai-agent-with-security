import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";
import { keycloak } from "../auth/keycloak";
import ErrorBoundary from "./ErrorBoundary";
import { Badge } from "./ui";

function useCountdown(expiresAtSeconds) {
  const [left, setLeft] = useState(0);
  useEffect(() => {
    const tick = () => setLeft(Math.max(0, Math.floor(keycloak.tokenParsed?.exp - Date.now() / 1000) || 0));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [expiresAtSeconds]);
  return left;
}

export default function Layout() {
  const { me, logout, can } = useAuth();
  const location = useLocation();
  const left = useCountdown(me?.token_expires_at); // access token lifetime; keycloak-js refreshes it transparently

  const links = [
    ["/", "Dashboard", true],
    ["/chat", "Agent chat", can("agent:execute")],
    ["/knowledge", "Knowledge base", can("document:read")],
    ["/users", "Users", can("user:read")],
    ["/roles", "Roles & permissions", can("role:read")],
    ["/agents", "Agents", can("agent:manage") || can("tool:configure")],
    ["/audit", "Audit logs", can("audit:read")],
  ];

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">◆</span> Enterprise AI
          <div className="muted small">Authn / Authz platform</div>
        </div>
        <nav>
          {links
            .filter(([, , visible]) => visible)
            .map(([to, label]) => (
              <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive ? "active" : "")}>
                {label}
              </NavLink>
            ))}
        </nav>
        <div className="whoami">
          <div className="who-name">{me.username}</div>
          <div className="who-tags">
            {me.roles.map((r) => (
              <Badge key={r} kind="info">
                {r}
              </Badge>
            ))}
            <Badge>{me.tenant_id}</Badge>
          </div>
          <div className="muted small">
            {me.department} · token {left > 0 ? `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` : "refreshing…"}
          </div>
          <button className="btn btn-ghost" onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="content">
        <p className="banner">
          Menu visibility is a UX hint. Every request is re-checked by the backend and Open Policy Agent.
        </p>
        <ErrorBoundary key={location.pathname}>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  );
}
