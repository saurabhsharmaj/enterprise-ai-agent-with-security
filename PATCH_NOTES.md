# Patch 2: native agent replaced by LangChain

Apply exactly like patch 1: unzip over your `enterprise-ai-security/` folder (your `.env` is untouched), then

```
docker compose up -d --build
```
`--build` is REQUIRED: the backend image now installs `langchain-core` and `langchain-anthropic` (needs internet during the build).
No OPA restart, no migration, no `down -v`. Existing `.env` keeps working (`AGENT_BRAIN=mock|llm`, `ANTHROPIC_API_KEY`).

## What changed
* New: `app/agents/lc_agent.py`, `lc_tools.py`, `lc_models.py`, `lc_factory.py` (LangChain agent, MCP-backed tools, chat models).
* Rewritten: `app/agents/orchestrator.py`. Trimmed: `brain.py` (now only shared data types).
* Removed: `app/agents/llm_brain.py`, `app/agents/factory.py` (delete them if they remain in your folder — the zip cannot delete files),
  and `backend/tests/unit/test_llm_brain.py`.
* `requirements.txt` (+2 packages), compose (LangSmith tracing forced off), chat response/audit now include `engine: "langchain"`,
  UI shows a "langchain" badge. README + docs updated.
* Security model unchanged: LangChain tools only call MCP, MCP only calls the executor, OPA decides.

## Delete these three stale files
```
del backend\app\agents\llm_brain.py backend\app\agents\factory.py backend\tests\unit\test_llm_brain.py     (Windows)
rm  backend/app/agents/llm_brain.py backend/app/agents/factory.py backend/tests/unit/test_llm_brain.py     (macOS/Linux)
```
(If you skip this nothing breaks: they are no longer imported anywhere, just dead code. Delete them to keep the project clean.)
