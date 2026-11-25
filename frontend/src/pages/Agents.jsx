import { useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { Badge, Card, ErrorBox, Loading, Table, statusBadge, when } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

function AgentCard({ agent, reload, onError }) {
  async function run(fn) {
    onError(null);
    try {
      await fn();
      reload();
    } catch (e) {
      onError(e);
    }
  }
  return (
    <div className="agent">
      <div className="row between">
        <div>
          <strong>{agent.name}</strong> <code>{agent.id}</code>{" "}
          {agent.enabled ? <Badge kind="ok">enabled</Badge> : <Badge kind="bad">disabled</Badge>}
        </div>
        <button className="btn btn-small" onClick={() => run(() => api.setAgentEnabled(agent.id, !agent.enabled))}>
          {agent.enabled ? "Disable agent" : "Enable agent"}
        </button>
      </div>
      <p className="muted small">{agent.description}</p>
      <Table
        rows={agent.tools.map((t) => ({ ...t, id: t.tool_name }))}
        columns={[
          { key: "tool_name", label: "Tool", render: (t) => <code>{t.tool_name}</code> },
          { key: "description", label: "Description" },
          { key: "enabled", label: "Enabled", render: (t) => (
              <input type="checkbox" checked={t.enabled}
                onChange={() => run(() => api.configureTool(agent.id, t.tool_name, { enabled: !t.enabled }))} />) },
          { key: "requires_approval", label: "Human approval", render: (t) => (
              <input type="checkbox" checked={t.requires_approval}
                onChange={() => run(() => api.configureTool(agent.id, t.tool_name, { requires_approval: !t.requires_approval }))} />) },
        ]}
      />
    </div>
  );
}

function Approvals() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi(() => api.approvals(), []);
  const [err, setErr] = useState(null);

  async function decide(id, d) {
    setErr(null);
    try {
      await api.decideApproval(id, d);
      reload();
    } catch (e) {
      setErr(e);
    }
  }
  return (
    <Card title="Human approval requests" actions={<button className="btn btn-ghost" onClick={reload}>Refresh</button>}>
      {loading && <Loading />}
      <ErrorBox error={error} />
      <ErrorBox error={err} />
      <Table
        rows={data?.approvals}
        empty="No approval requests."
        columns={[
          { key: "created_at", label: "Created", render: (r) => when(r.created_at) },
          { key: "tool_name", label: "Tool", render: (r) => <code>{r.tool_name}</code> },
          { key: "resource_id", label: "Resource" },
          { key: "requester", label: "Requester", render: (r) => r.requester_username || r.requester_id },
          { key: "status", label: "Status", render: (r) => statusBadge(r.status) },
          { key: "expires_at", label: "Expires", render: (r) => when(r.expires_at) },
          { key: "act", label: "", render: (r) => r.status === "PENDING" && can("approval_request:decide") ? (
              <>
                <button className="btn btn-small" onClick={() => decide(r.id, "APPROVE")}>Approve</button>{" "}
                <button className="btn btn-small btn-danger" onClick={() => decide(r.id, "REJECT")}>Reject</button>
              </>) : null },
        ]}
      />
      <p className="muted small">
        An approved request lets the original requester repeat the exact same action once. You cannot decide your own
        request (separation of duties is enforced in policy).
      </p>
    </Card>
  );
}

export default function Agents() {
  const { data, error, loading, reload } = useApi(() => api.agents(), []);
  const [err, setErr] = useState(null);
  return (
    <>
      <h1>Agents</h1>
      <Card title="Agent & tool configuration">
        {loading && <Loading />}
        <ErrorBox error={error} />
        <ErrorBox error={err} />
        {data?.agents.map((a) => <AgentCard key={a.id} agent={a} reload={reload} onError={setErr} />)}
        <p className="muted small">
          Disabling an agent or tool takes effect immediately: the policy checks the stored flag on every call.
        </p>
      </Card>
      <Approvals />
    </>
  );
}
