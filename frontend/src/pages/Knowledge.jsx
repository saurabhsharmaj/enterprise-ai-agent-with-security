import { useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { Badge, Card, ErrorBox, Loading, Table } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

const LEVELS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];

export default function Knowledge() {
  const { can } = useAuth();
  const docs = useApi(() => api.documents(), []);
  const [form, setForm] = useState({ title: "", body: "", classification: "INTERNAL" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(null);

  async function add(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const r = await api.createDocument(form);
      setDone(`Added "${r.title}" (${r.chunks} chunk${r.chunks === 1 ? "" : "s"} indexed).`);
      setForm({ title: "", body: "", classification: "INTERNAL" });
      docs.reload();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const rows = Array.isArray(docs.data?.documents) ? docs.data.documents : [];
  return (
    <>
      <h1>Knowledge base</h1>
      <p className="muted">
        Documents the agent can search and cite (RAG). You only see documents your role, department and clearance allow —
        the agent is filtered the same way, by the same policy, before anything is ranked.
      </p>
      <Card title="Documents you may read">
        {docs.loading && <Loading />}
        <ErrorBox error={docs.error} />
        <Table
          rows={rows}
          columns={[
            { key: "title", label: "Title" },
            { key: "department", label: "Department" },
            { key: "classification", label: "Classification", render: (r) => <Badge>{r.classification}</Badge> },
            { key: "chunks", label: "Indexed chunks" },
          ]}
        />
      </Card>
      {can("document:create") && (
        <Card title="Add a document">
          <form onSubmit={add} className="stack">
            <input placeholder="Title" value={form.title} minLength={3} maxLength={200} required
              onChange={(e) => setForm({ ...form, title: e.target.value })} />
            <textarea placeholder="Content (plain text)" rows={6} value={form.body} minLength={10} maxLength={20000} required
              onChange={(e) => setForm({ ...form, body: e.target.value })} />
            <div className="row">
              <select value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })}>
                {LEVELS.map((l) => <option key={l}>{l}</option>)}
              </select>
              <button className="btn btn-primary" disabled={busy}>Add &amp; index</button>
            </div>
          </form>
          <ErrorBox error={error} />
          {done && <div className="alert">{done}</div>}
        </Card>
      )}
    </>
  );
}
