import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthProvider";
import Layout from "./components/Layout";
import { Loading } from "./components/ui";
import AgentChat from "./pages/AgentChat";
import Agents from "./pages/Agents";
import AuditLogs from "./pages/AuditLogs";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import Roles from "./pages/Roles";
import Users from "./pages/Users";

export default function App() {
  const { ready, authenticated, me, error } = useAuth();
  if (!ready) return <div className="login"><Loading what="Contacting Keycloak" /></div>;
  if (!authenticated || !me) return <Login error={error} />;

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="chat" element={<AgentChat />} />
        <Route path="users" element={<Users />} />
        <Route path="roles" element={<Roles />} />
        <Route path="agents" element={<Agents />} />
        <Route path="audit" element={<AuditLogs />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
