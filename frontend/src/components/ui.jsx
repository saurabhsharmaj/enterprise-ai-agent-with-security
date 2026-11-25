import { ApiError } from "../services/api";

export function Badge({ kind = "neutral", children }) {
  return <span className={`badge badge-${kind}`}>{children}</span>;
}

export function Loading({ what = "Loading" }) {
  return <p className="muted">{what}…</p>;
}

// Shows backend errors. Authorization denials (403) get a prominent, readable treatment.
export function ErrorBox({ error }) {
  if (!error) return null;
  const denied = error instanceof ApiError && error.status === 403;
  const limited = error instanceof ApiError && error.status === 429;
  return (
    <div className={`alert ${denied ? "alert-denied" : "alert-error"}`} role="alert">
      <strong>{denied ? "Access denied" : limited ? "Slow down" : "Request failed"}</strong>
      <div>{error.message}</div>
      {error.reasons?.length > 0 && (
        <div className="reasons">
          {error.reasons.map((r) => (
            <code key={r}>{r}</code>
          ))}
        </div>
      )}
      {error.detail?.correlation_id && <div className="muted small">correlation id: {error.detail.correlation_id}</div>}
    </div>
  );
}

export function Card({ title, actions, children }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-head">
          <h2>{title}</h2>
          <div>{actions}</div>
        </header>
      )}
      {children}
    </section>
  );
}

export function Table({ columns, rows, empty = "Nothing to show." }) {
  if (!rows?.length) return <p className="muted">{empty}</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={r.id ?? r.audit_id ?? i}>
              {columns.map((c) => (
                <td key={c.key}>{c.render ? c.render(r) : String(r[c.key] ?? "")}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export const money = (v) =>
  v === null || v === undefined ? "" : Number(v).toLocaleString(undefined, { style: "currency", currency: "USD" });

export const when = (v) => (v ? new Date(v).toLocaleString() : "");

export function statusBadge(s) {
  const map = { success: "ok", SUCCESS: "ok", ALLOW: "ok", APPROVED: "ok", PENDING: "warn", pending_approval: "warn",
    PENDING_APPROVAL: "warn", DENY: "bad", denied: "bad", NOT_EXECUTED: "neutral", FAILED: "bad", error: "bad",
    not_found: "bad", invalid_arguments: "bad", REJECTED: "bad", EXECUTED: "ok" };
  return <Badge kind={map[s] || "neutral"}>{s}</Badge>;
}
