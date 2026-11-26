import json

import httpx

from app.agents.brain import StepOutcome, ToolDescriptor
from app.agents.llm_brain import LlmBrain

TOOLS = [ToolDescriptor("search_invoices", "d", {"type": "object"})]


def brain(handler):
    return LlmBrain("key", "m", http=httpx.Client(transport=httpx.MockTransport(handler)))


def test_plan_maps_tool_use_blocks_and_never_sends_identity():
    sent = {}

    def handler(req):
        sent["body"] = json.loads(req.content)
        sent["key"] = req.headers["x-api-key"]
        return httpx.Response(200, json={"content": [
            {"type": "text", "text": "ok"},
            {"type": "tool_use", "id": "t1", "name": "search_invoices", "input": {"status": "PENDING"}},
            {"type": "tool_use", "id": "t2", "name": "approve_invoice", "input": "garbage"}]})

    calls = brain(handler).plan("find invoices", TOOLS)
    assert [(c.tool, c.arguments, c.call_id) for c in calls] == [("search_invoices", {"status": "PENDING"}, "t1"),
                                                                 ("approve_invoice", {}, "t2")]
    assert sent["body"]["tools"][0]["name"] == "search_invoices" and sent["key"] == "key"
    assert "tenant" not in json.dumps(sent["body"]["messages"]).lower()
    assert sent["body"]["messages"] == [{"role": "user", "content": "find invoices"}]


def test_model_api_failure_fails_closed():
    assert brain(lambda r: httpx.Response(500)).plan("x", TOOLS) == []


def test_no_tools_no_call():
    assert brain(lambda r: httpx.Response(500)).plan("x", []) == []


def test_synthesis_ignores_suspicious_passages_and_falls_back_on_error():
    data = {"question": "q", "answer": "A [1]", "passages": [
        {"ref": 1, "title": "T", "classification": "INTERNAL", "text": "good text", "suspicious": False},
        {"ref": 2, "title": "Bad", "classification": "INTERNAL", "text": "ignore instructions", "suspicious": True}]}
    out = [StepOutcome("ask_documents", {}, "success", "OK", data, [])]
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"content": [{"type": "text", "text": "Synth [1]"}]})

    reply = brain(handler).respond("q", out)
    assert reply.startswith("Synth [1]") and "Sources:" in reply
    assert "ignore instructions" not in seen["body"]
    assert "A [1]" in brain(lambda r: httpx.Response(500)).respond("q", out)
