import { useState } from "react";
import { Card, ErrorBox, Loading, Table, statusBadge, when } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

const PAGE = 25;

export default function AuditLogs() {
  const [decision, setDecision] = useState("");
  const [cid, setCid] = useState("");
  const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useApi(
    () => api.auditLogs({ limit: PAGE, offset, decision, correlation_id: cid }),
    [decision, cid, offset]
  );
  const rows = data?.audit_logs;

  return (
    <>
      <h1>Audit logs</h1>
      <Card title="Authorization and execution history (your tenant)" actions={<button className="btn btn-ghost" onClick={reload}>Refresh</button>}>
        <div className="row">
          <select value={decision} onChange={(e) => { setOffset(0); setDecision(e.target.value); }}>
            <option value="">all decisions</option>
            <option>ALLOW</option>
            <option>DENY</option>
            <option>PENDING</option>
          </select>
          <input value={cid} onChange={(e) => { setOffset(0); setCid(e.target.value.trim()); }} placeholder="filter by correlation id" />
        </div>
        {loading && <Loading />}
        <ErrorBox error={error} />
        <Table
          rows={rows}
          columns={[
            { key: "occurred_at", label: "Time", render: (r) => when(r.occurred_at) },
            { key: "username", label: "User" },
            { key: "channel", label: "Via" },
            { key: "agent_id", label: "Agent" },
            { key: "tool_name", label: "Tool", render: (r) => r.tool_name && <code>{r.tool_name}</code> },
            { key: "resource", label: "Resource", render: (r) => [r.resource_type, r.resource_id].filter(Boolean).join(" / ") },
            { key: "action", label: "Action" },
            { key: "decision", label: "Decision", render: (r) => statusBadge(r.decision) },
            { key: "execution_status", label: "Execution", render: (r) => statusBadge(r.execution_status) },
            { key: "reason", label: "Reason", render: (r) => <span className="small">{r.reason}</span> },
            { key: "correlation_id", label: "Correlation", render: (r) => (
                <button className="link small" onClick={() => { setOffset(0); setCid(r.correlation_id); }}>{r.correlation_id.slice(0, 8)}…</button>) },
          ]}
        />
        <div className="row">
          <button className="btn btn-small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
          <button className="btn btn-small" disabled={!rows || rows.length < PAGE} onClick={() => setOffset(offset + PAGE)}>Next</button>
          <span className="muted small">showing {offset + 1}–{offset + (rows?.length || 0)}</span>
        </div>
        <p className="muted small">
          Append-only: the application's database role can insert and read audit rows but never update or delete them.
          Tokens, passwords and prompt text are never recorded.
        </p>
      </Card>
    </>
  );
}
