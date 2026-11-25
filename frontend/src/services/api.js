// Thin API client. The only credential sent is the user's own access token. The client NEVER sends a
// user id, tenant or role: the backend derives all of that from the validated token and the database.
import { getToken } from "../auth/keycloak";

const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail?.message || detail?.error || `HTTP ${status}`);
    this.status = status;
    this.detail = detail || {};
    this.reasons = detail?.reasons || [];
  }
}

async function request(method, path, body, retry = true) {
  const token = await getToken();
  const res = await fetch(BASE + path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && retry) {
    await getToken(true); // token may have been revoked/expired between refresh and use
    return request(method, path, body, false);
  }
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const d = data?.detail;
    throw new ApiError(res.status, typeof d === "object" && d !== null ? d : { error: String(d || res.statusText) });
  }
  return { status: res.status, data };
}

const get = (p) => request("GET", p).then((r) => r.data);
const post = (p, b) => request("POST", p, b ?? {});
const patch = (p, b) => request("PATCH", p, b).then((r) => r.data);
const qs = (o) => {
  const p = new URLSearchParams(Object.entries(o).filter(([, v]) => v !== undefined && v !== "" && v !== null));
  const s = p.toString();
  return s ? `?${s}` : "";
};

export const api = {
  me: () => get("/api/me"),
  agents: () => get("/api/agents"),
  agent: (id) => get(`/api/agents/${id}`),
  chat: (id, message) => post(`/api/agents/${id}/chat`, { message }).then((r) => r.data),
  setAgentEnabled: (id, enabled) => patch(`/api/agents/${id}`, { enabled }),
  configureTool: (id, tool, cfg) => patch(`/api/agents/${id}/tools/${tool}`, cfg),
  invoices: (f = {}) => get(`/api/invoices${qs(f)}`),
  invoice: (id) => get(`/api/invoices/${id}`),
  approveInvoice: (id) => post(`/api/invoices/${id}/approve`), // resolves with {status, data} (200 or 202)
  createPurchaseOrder: (body) => post("/api/purchase-orders", body),
  authorizationCheck: (body) => post("/api/authorization/check", body).then((r) => r.data),
  users: () => get("/api/users"),
  updateUser: (id, body) => patch(`/api/users/${id}`, body),
  roles: () => get("/api/roles"),
  permissions: () => get("/api/permissions"),
  auditLogs: (f = {}) => get(`/api/audit-logs${qs(f)}`),
  approvals: () => get("/api/approvals"),
  decideApproval: (id, decision) => post(`/api/approvals/${id}/decision`, { decision }).then((r) => r.data),
};
