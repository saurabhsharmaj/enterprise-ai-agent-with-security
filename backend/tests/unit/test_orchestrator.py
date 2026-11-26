"""Orchestrator: brain decides, MCP carries, executor authorises. Proven with fakes."""
from types import SimpleNamespace

import pytest

from app.agents import orchestrator as orch
from app.agents.brain import PlannedCall
from app.agents.finance_agent import MockFinanceBrain
from app.agents.results import ToolResult
from app.guardrails import Guardrails
from app.mcp import server as mcp_server


class FakeDb:
    def rollback(self):
        pass


class FakeExecutor:
    def __init__(self, reply=None):
        self.calls, self.reply = [], reply

    def execute(self, ctx, tool, args, *, agent_id=None):
        self.calls.append((tool, args, agent_id))
        if self.reply:
            return self.reply(tool, args)
        return ToolResult(tool, "success", True, ["allowed_by_policy"], "OK", data={"count": 0, "invoices": []})


class FakeAudit:
    def __init__(self):
        self.events = []

    def record(self, e):
        self.events.append(e)
        return "audit-1"


@pytest.fixture()
def env(monkeypatch):
    tools = [{"tool_name": n, "enabled": True, "requires_approval": False, "description": ""}
             for n in ("search_invoices", "read_invoice", "approve_invoice", "ask_documents", "search_documents",
                       "create_purchase_order")]
    monkeypatch.setattr(mcp_server.agents_repo, "list_tools", lambda *a: tools)
    p = SimpleNamespace(tenant_id="TENANT_A", user_id="u", username="bob")
    return SimpleNamespace(principal=p, db=FakeDb(), correlation_id="cid-12345678")


def make(brains=None, executor=None, mode="monitor"):
    ex, audit = executor or FakeExecutor(), FakeAudit()
    return orch.AgentOrchestrator(ex, audit, brains or {"FINANCE_AGENT": MockFinanceBrain()}, Guardrails(mode)), ex, audit


def test_brain_choice_is_executed_through_mcp_and_executor(env):
    o, ex, audit = make()
    out = o.run(env, "FINANCE_AGENT", "Find my pending invoices.")
    assert ex.calls == [("search_invoices", {"status": "PENDING", "mine": True}, "FINANCE_AGENT")]
    assert out.transport == "mcp" and out.steps[0].audit_id is None or out.steps[0].status == "success"
    assert audit.events[-1].action == "chat" and audit.events[-1].detail["transport"] == "mcp"


def test_rag_question_is_routed_to_ask_documents(env):
    o, ex, _ = make()
    o.run(env, "FINANCE_AGENT", "What is the expense reimbursement policy?")
    assert ex.calls[0][0] == "ask_documents"


def test_denial_from_the_executor_reaches_the_user_unchanged(env):
    deny = lambda tool, args: ToolResult(tool, "denied", False, ["approval_limit_exceeded"], "Denied: over your limit.")
    o, _, _ = make(executor=FakeExecutor(deny))
    out = o.run(env, "FINANCE_AGENT", "Approve invoice INV-1002.")
    assert out.steps[0].status == "denied" and "over your limit" in out.reply


class GreedyBrain:
    """A brain that tries to do far more than it should (prompt-injected LLM stand-in)."""
    def plan(self, message, tools):
        return [PlannedCall("search_invoices", {}), PlannedCall("approve_invoice", {"invoice_id": "INV-1"}),
                PlannedCall("approve_invoice", {"invoice_id": "INV-2"}), PlannedCall("approve_invoice", {"invoice_id": "INV-3"}),
                PlannedCall("approve_invoice", {"invoice_id": "INV-4"})]

    def respond(self, message, outcomes):
        return "done"


def test_step_cap_limits_fan_out(env):
    o, ex, _ = make({"FINANCE_AGENT": GreedyBrain()})
    o.run(env, "FINANCE_AGENT", "go")
    assert len(ex.calls) == orch.MAX_STEPS


class LeakyBrain(GreedyBrain):
    def plan(self, message, tools):
        return []

    def respond(self, message, outcomes):
        return "Here is your token: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.c2lnbmF0dXJlMTIzNDU2 and Bearer abcdefghijklmnopqrstuvwxyz0123"


def test_secrets_in_replies_are_redacted_and_flagged(env):
    o, _, audit = make({"FINANCE_AGENT": LeakyBrain()})
    out = o.run(env, "FINANCE_AGENT", "hi")
    assert "eyJ" not in out.reply and "Bearer abc" not in out.reply
    assert "redacted_jwt" in out.guardrails and "redacted_jwt" in audit.events[-1].detail["guardrail_flags"]


def test_poisoned_document_is_flagged_in_audit(env):
    data = {"count": 1, "flagged_passages": 1, "answer": None, "passages": []}
    rag = lambda tool, args: ToolResult(tool, "success", True, [], "OK", data=data)
    o, _, audit = make(executor=FakeExecutor(rag))
    out = o.run(env, "FINANCE_AGENT", "What is the expense policy?")
    assert "injection_in_retrieved_document" in out.guardrails


def test_unknown_agent_has_no_brain():
    o, _, _ = make()
    assert o.has_brain("FINANCE_AGENT") and not o.has_brain("OTHER")
