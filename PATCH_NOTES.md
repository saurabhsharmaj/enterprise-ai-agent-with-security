# Patch: MCP + RAG + guardrails + LLM brain + chat fix

## Apply (from the folder that CONTAINS your `enterprise-ai-security/` directory)
1. Unzip `enterprise-ai-security-patch.zip` there and let it overwrite/merge. It never touches your `.env`.
2. Add to your `.env` (optional; defaults keep the mock agent): see the new block at the end of `.env.example`.
3. Rebuild and re-run migrations + seed, and make OPA reload its policy files:
   ```
   docker compose up -d --build
   docker compose restart opa
   docker compose up -d --build backend frontend     # if anything is still on the old image
   ```
   (`migrate` runs automatically: migration 0002 + idempotent seed. No `down -v` needed; your data and Keycloak users stay.)
4. Log out and in again (new permissions `document:read/create` come from the DB).
5. Run tests:
   ```
   docker compose --profile test run --rm opa-tests     # 110 expected
   docker compose --profile test run --rm tests
   ```
   Changed existing test: `tests/integration/test_agent_chat.py` now expects the 6th tool `ask_documents`.

## What is in it
* Blank chat page: crash-proof chat rendering (every response field normalised), per-message and per-page error
  boundaries that show the real error text instead of a white page.
* Embedded MCP server + client; orchestrator discovers and executes tools through MCP; `POST /mcp/{agent_id}` for external clients.
* RAG: chunking, embeddings, permission-filtered retrieval (OPA before ranking), `ask_documents` tool with citations,
  Knowledge-base page, `/api/documents`, seeded corpus.
* Guardrails (monitor/block), secret redaction, step cap; optional Claude brain (`AGENT_BRAIN=llm`).
* Seed fix: all parameters cast (the `AmbiguousParameter` migrate error cannot recur).
* Docs: `docs/AGENT_PLATFORM.md`.

## If the chat page ever still goes blank
Press F12 → Console, send the message again and copy the red error. The new boundary also prints the message on screen.
