# Agent platform: LangChain agent, MCP, RAG, guardrails

## 1. How a chat message flows now

```
Browser ──Bearer token──▶ POST /api/agents/{id}/chat
   1. Keycloak JWT validated (sig, iss, aud, exp, azp) → Principal (identity from token + DB only)
   2. OPA: may this user execute this agent?                         (deny → 403, audited)
   3. Guardrails: input scan (monitor: flag + audit │ block: 422)
   4. Orchestrator ── MCP client ──▶ MCP server (in-process, built FOR this user's request context)
         initialize → tools/list      the tool catalogue the model may choose from (no identity in it)
   5. LangChain agent (app/agents/lc_agent.py): chat model DECIDES which tools to call, possibly over several
      rounds (hard cap: 3 tool calls per message)                  ← the only thing the model does
   6. Each LangChain tool → MCP tools/call ─▶ ToolExecutor: strict args → DB-loaded resource → OPA → human-approval gate → execute → audit
   7. Model writes the reply from the (untrusted-wrapped) tool results; guardrails redact secrets; chat-level audit row (no prompt text)
```

The MCP layer is a *standard interface*, not a new trust boundary: the server is constructed from the authenticated
request context, `tools/call` can only reach `ToolExecutor`, and identity/tenant/role are never part of the protocol
payload (extra argument fields are rejected by the strict schemas).

## 2. MCP

| | |
|---|---|
| Server code | `backend/app/mcp/server.py` (JSON-RPC 2.0: `initialize`, `ping`, `tools/list`, `tools/call`; protocol 2025-06-18) |
| Client code | `backend/app/mcp/client.py` (`InProcessTransport` used by the orchestrator; `HttpTransport` for any remote MCP server) |
| External endpoint | `POST /mcp/{agent_id}` — same Keycloak bearer auth, same agent-level OPA check, same executor, Origin + `MCP-Protocol-Version` validation, no batching, no SSE |
| Tool annotations | `readOnlyHint` / `destructiveHint` derived from the tool's action |
| Results | `isError: true` for denied/failed calls (the `structuredContent` carries status, reasons, audit id); `pending_approval` is *not* an error |

Try it (token from the CLI client, dev only):

```bash
TOKEN=$(curl -s -d grant_type=password -d client_id=enterprise-ai-cli -d username=charlie -d 'password=Charlie#Dev2026' \
  http://localhost:8080/realms/enterprise-ai/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s localhost:8000/mcp/FINANCE_AGENT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"approve_invoice","arguments":{"invoice_id":"INV-1001"}}}'
# → isError: true, status "denied" (charlie is an EMPLOYEE)
```

## 3. RAG

* **Tables**: `document_chunks` (migration `0002`): tenant-scoped, RLS forced, chunk text + `real[]` embedding.
* **Ingest**: `app/rag/chunker.py` (sentence-aware, ~600 chars, overlap) → `embedder.py` (deterministic feature-hashing, 256-d, no model download) → `repository.py`. Seeded by `app.seed`; new documents via the **Knowledge base** page / `POST /api/documents`.
* **Retrieve** (`app/rag/service.py`), in this order — the order is the security property:
  1. load the tenant's chunks (RLS + explicit `tenant_id`),
  2. **OPA `allowed_ids` decides which parent documents the caller may read** (tenant, department, clearance),
  3. only then rank (0.6 cosine + 0.4 keyword overlap), cap 2 chunks/document, return with citations.
  Unauthorised text never reaches ranking, the agent, the reply, the logs or the model.
* **Tool**: `ask_documents(question, top_k)` — an ordinary registry tool, so it is authorised (`document:search`), human-approval-gateable, rate-limited and audited like every other tool. Answer is extractive with `[n]` citations; with `AGENT_BRAIN=llm` Claude writes the answer from the permitted passages only (passages are passed as untrusted data).
* **Production upgrade path**: replace `HashingEmbedder` with a neural embedder (implement `Embedder`), and `real[]` + Python cosine with pgvector (`vector` column + HNSW index). Keep step 2 (authorise first) — with pgvector, add the OPA-derived document-id list as a `WHERE document_id = ANY(...)` filter (post-filter with a larger `LIMIT` for big corpora).
* Seed corpus exercises the filters: *Executive Compensation Bands* (RESTRICTED, admin only), *IT Access Control Standard* (IT only), Tenant B documents (never visible to Tenant A).

## 4. Guardrails (`app/guardrails/`, `GUARDRAIL_MODE=off|monitor|block`, default `monitor`)

Guardrails are **defence in depth, not the security boundary** — OPA and the executor are.

| Guardrail | monitor (default) | block |
|---|---|---|
| Injection-like user input (ignore instructions, "as admin", "TENANT_x", prompt exfiltration, bypass auth) | flagged in response + audit | HTTP 422 `guardrail_blocked` |
| Injection-like text inside retrieved documents / new documents | passage marked `suspicious` | passage withheld; new document rejected |
| Secrets in replies (JWT, Bearer, API keys, AWS keys, private keys, `password=`) | redacted + flagged | same |
| Fan-out | `MAX_STEPS = 3` tool calls per message (always) | same |

## 5. The LangChain agent

The agent runtime is **LangChain** (`langchain-core` + `langchain-anthropic`). Files:

| File | Role |
|---|---|
| `app/agents/lc_agent.py` | `LangChainAgent`: bounded tool-calling loop (`bind_tools` → `invoke` → `ToolMessage`), fail-closed on model errors, 3-call budget, hallucinated tool names still routed to the executor (denied + audited) |
| `app/agents/lc_tools.py` | LangChain `StructuredTool`s whose function is `McpClient.call_tool`; results are shown to the model as `<tool_result untrusted="true">` and flagged RAG passages are withheld |
| `app/agents/lc_models.py` | `build_chat_model`: `ChatAnthropic` or the deterministic `DeterministicFinanceModel` |
| `app/agents/lc_factory.py` | one agent per agent id; model created once |
| `app/agents/orchestrator.py` | MCP handshake + tool discovery, runs the agent, guardrails, chat-level audit |

| `AGENT_BRAIN` | Chat model |
|---|---|
| `mock` (default) | `DeterministicFinanceModel` — a LangChain `BaseChatModel` driven by fixed rules; no API key, no network. The loop, tool calls and ToolMessages are the real LangChain ones. |
| `llm` + `ANTHROPIC_API_KEY` | `ChatAnthropic(model=LLM_MODEL)` (default `claude-sonnet-5-5`). It never sees identity, roles, tenant, limits or tokens. API failure ⇒ **no tools run**. Empty key ⇒ falls back to `mock` with a warning. |

Security rules that did not change: LangChain has **no other route to data** — tools only call MCP, MCP only calls the executor.
Do **not** add tools that touch repositories or the database directly. Keep `LANGSMITH_TRACING=false` (compose sets it):
traces would send prompts and tenant data to a third party. If you want tracing, self-host it and review what is logged first.

## 6. What changed in the database/policy

* Migration `0002_rag_chunks` (additive; run automatically by the `migrate` job).
* `opa/policies/data.json`: tool `ask_documents`; permission `document:create` for ADMIN, MANAGER.
* `opa/policies/authz.rego`: one rule — documents can only be created in the author's own department (admins: any).
* `app/seed.py` is idempotent: existing rows are kept; new tool/documents/chunks/permissions are added.
