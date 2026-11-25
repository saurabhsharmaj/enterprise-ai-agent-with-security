import { useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { Badge, Card, ErrorBox, Loading, Table, money, statusBadge, when } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

function Identity() {
  const { me } = useAuth();
  const rows = [
    ["User", `${me.username} (${me.email || "no email"})`],
    ["User id (token sub)", <code key="i">{me.id}</code>],
    ["Tenant", me.tenant_id],
    ["Department", me.department],
    ["Roles", me.roles.join(", ") || "none"],
    ["Groups", me.groups.join(", ") || "none"],
    ["Approval limit", money(me.approval_limit)],
    ["Access token expires", when(me.token_expires_at * 1000)],
  ];
  return (
    <Card title="Who the backend thinks you are">
      <dl className="kv">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      <p className="muted small">
        Derived server-side from the validated JWT and the database. Permissions granted to you:{" "}
        {me.permissions.map((p) => (
          <Badge key={p}>{p}</Badge>
        ))}
      </p>
    </Card>
  );
}

function Agents() {
  const { data, error, loading } = useApi(() => api.agents(), []);
  return (
    <Card title="Available agents and tools">
      {loading && <Loading />}
      <ErrorBox error={error} />
      {data?.agents.map((a) => (
        <div key={a.id} className="agent">
          <div>
            <strong>{a.name}</strong> <code>{a.id}</code>{" "}
            {a.enabled ? <Badge kind="ok">enabled</Badge> : <Badge kind="bad">disabled</Badge>}{" "}
            {a.can_execute ? (
              <Badge kind="ok">you can run it</Badge>
            ) : (
              <Badge kind="bad">you cannot run it: {a.execute_denied_reasons.join(", ")}</Badge>
            )}
          </div>
          <p className="muted small">{a.description}</p>
          <div className="tags">
            {a.tools.map((t) => (
              <Badge key={t.tool_name} kind={t.enabled ? "info" : "bad"}>
                {t.tool_name}
                {t.requires_approval ? " 🛡" : ""}
              </Badge>
            ))}
          </div>
        </div>
      ))}
      <p className="muted small">🛡 = human approval gate enabled for this tool.</p>
    </Card>
  );
}

function AuthzProbe() {
  const [action, setAction] = useState("approve");
  const [rtype, setRtype] = useState("invoice");
  const [rid, setRid] = useState("INV-1001");
  const [out, setOut] = useState(null);
  const [err, setErr] = useState(null);

  async function run(e) {
    e.preventDefault();
    setErr(null);
    try {
      setOut(await api.authorizationCheck({ action, resource_type: rtype, ...(rid ? { resource_id: rid } : {}) }));
    } catch (x) {
      setOut(null);
      setErr(x);
    }
  }
  return (
    <Card title="Ask the policy engine (dry run, about you only)">
      <form className="row" onSubmit={run}>
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          {["read", "search", "approve", "create", "manage", "configure", "decide"].map((a) => (
            <option key={a}>{a}</option>
          ))}
        </select>
        <select value={rtype} onChange={(e) => setRtype(e.target.value)}>
          {["invoice", "document", "purchase_order", "user", "role", "permission", "audit", "agent", "approval_request"].map((a) => (
            <option key={a}>{a}</option>
          ))}
        </select>
        <input value={rid} onChange={(e) => setRid(e.target.value)} placeholder="INV-1001 (invoices only)" />
        <button className="btn">Check</button>
      </form>
      <ErrorBox error={err} />
      {out && (
        <div className={`alert ${out.allowed ? "alert-ok" : "alert-denied"}`}>
          <strong>{out.allowed ? "ALLOWED" : "DENIED"}</strong>
          <div>{out.explanation}</div>
          <div className="reasons">
            {out.reasons.map((r) => (
              <code key={r}>{r}</code>
            ))}
          </div>
        </div>
      )}
      <p className="muted small">
        The server builds the OPA input from your token and database records. You cannot supply a subject, tenant or
        attributes.
      </p>
    </Card>
  );
}

function Invoices() {
  const { data, error, loading, reload } = useApi(() => api.invoices({ limit: 50 }), []);
  const [msg, setMsg] = useState(null);
  const [err, setErr] = useState(null);

  async function approve(id) {
    setMsg(null);
    setErr(null);
    try {
      const r = await api.approveInvoice(id);
      setMsg(r.status === 202 ? `${id}: ${r.data.message}` : `${id} approved.`);
      reload();
    } catch (x) {
      setErr(x);
    }
  }
  return (
    <Card title="Invoices you may see" actions={<button className="btn btn-ghost" onClick={reload}>Refresh</button>}>
      {loading && <Loading />}
      <ErrorBox error={error} />
      <ErrorBox error={err} />
      {msg && <div className="alert alert-ok">{msg}</div>}
      <Table
        rows={data?.data?.invoices}
        columns={[
          { key: "id", label: "Invoice" },
          { key: "vendor", label: "Vendor" },
          { key: "amount", label: "Amount", render: (r) => money(r.amount) },
          { key: "status", label: "Status", render: (r) => statusBadge(r.status) },
          { key: "department", label: "Dept" },
          { key: "classification", label: "Class." },
          { key: "owner", label: "Owner" },
          { key: "act", label: "", render: (r) => (r.status === "PENDING" ? <button className="btn btn-small" onClick={() => approve(r.id)}>Approve</button> : null) },
        ]}
      />
      <p className="muted small">
        The Approve button is always shown for pending invoices on purpose: try it as Charlie, or on a large invoice, and
        watch the backend refuse with the policy reason.
      </p>
    </Card>
  );
}

export default function Dashboard() {
  return (
    <>
      <h1>Dashboard</h1>
      <div className="grid2">
        <Identity />
        <Agents />
      </div>
      <Invoices />
      <AuthzProbe />
    </>
  );
}
