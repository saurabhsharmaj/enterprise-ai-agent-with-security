"""ToolExecutor guarantees, proven with fakes (no DB / OPA needed):
  * a tool body NEVER runs unless OPA said allow, and OPA is called immediately before it;
  * OPA failure => deny and no execution;
  * every outcome (allow, deny, invalid, unknown, failed) writes exactly one audit record;
  * the executor never trusts anything the model proposed beyond schema-valid arguments."""
import uuid
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, ConfigDict

from app.agents import tool_executor as te
from app.agents.tool_executor import ToolExecutor
from app.authorization.opa_client import Decision, deny
from app.core.security import Principal, RequestContext
from app.tools.base import Resolved, ToolSpec
from tests.conftest import SETTINGS


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")
    thing: str


class FakeOpa:
    def __init__(self, decision: Decision, journal: list):
        self.decision, self.journal, self.payloads = decision, journal, []

    def decide_tool(self, payload):
        self.journal.append("opa")
        self.payloads.append(payload)
        return self.decision

    def allowed_ids(self, *a, **k):
        return set()


class FakeAudit:
    def __init__(self):
        self.events = []

    def record(self, ev):
        self.events.append(ev)
        return uuid.uuid4()


def make(decision: Decision, *, resolved: Resolved | None = Resolved({"type": "thing", "id": "T1", "tenant_id": "TENANT_A"}),
         raises: Exception | None = None):
    journal: list[str] = []

    def execute(ctx, args, res):
        journal.append("execute")
        if raises:
            raise raises
        return {"ok": True}

    spec = ToolSpec("do_thing", "x", "thing", "do", Args, lambda ctx, a: resolved, execute)
    opa, audit = FakeOpa(decision, journal), FakeAudit()
    executor = ToolExecutor(opa, audit, SETTINGS, registry={"do_thing": spec})
    return executor, opa, audit, journal


@pytest.fixture(autouse=True)
def no_db(monkeypatch):
    monkeypatch.setattr(te.agents_repo, "tool_requires_approval_anywhere", lambda *a, **k: False)
    monkeypatch.setattr(te.agents_repo, "get_agent", lambda *a, **k: {"id": "A", "enabled": True, "tenant_id": "TENANT_A"})
    monkeypatch.setattr(te.agents_repo, "get_tool", lambda *a, **k: {"tool_name": "do_thing", "enabled": True, "requires_approval": False})
    monkeypatch.setattr(te.approvals_repo, "find", lambda *a, **k: None)


@pytest.fixture()
def ctx():
    p = Principal(uuid.uuid4(), "bob", "TENANT_A", ("MANAGER",), (), "FINANCE", 10000.0, None, 0)
    return RequestContext(principal=p, db=MagicMock(), correlation_id="cid-123456789")


def test_allowed_call_runs_after_opa_and_is_audited(ctx):
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)))
    r = ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="A")
    assert r.status == "success" and r.data == {"ok": True}
    assert journal == ["opa", "execute"]            # authorisation immediately precedes execution
    assert len(audit.events) == 1 and audit.events[0].decision == "ALLOW" and audit.events[0].execution_status == "SUCCESS"
    ctx.db.commit.assert_called()


def test_denied_call_never_executes(ctx):
    ex, opa, audit, journal = make(Decision(False, ("missing_permission",)))
    r = ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="A")
    assert r.status == "denied" and not r.allowed and r.data is None
    assert journal == ["opa"]
    assert len(audit.events) == 1 and audit.events[0].decision == "DENY" and audit.events[0].execution_status == "NOT_EXECUTED"
    assert audit.events[0].reason == "missing_permission"


def test_opa_outage_denies_and_never_executes(ctx):
    ex, opa, audit, journal = make(deny("opa_unavailable"))
    r = ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="A")
    assert r.status == "denied" and "execute" not in journal
    assert audit.events[0].reason == "opa_unavailable"


def test_unknown_tool_is_denied_without_calling_opa_or_executing(ctx):
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)))
    r = ex.execute(ctx, "drop_database", {}, agent_id="A")
    assert r.status == "denied" and r.reasons == ["tool_unknown"]
    assert journal == []
    assert len(audit.events) == 1 and audit.events[0].decision == "DENY"


def test_extra_arguments_are_rejected_before_opa(ctx):
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)))
    r = ex.execute(ctx, "do_thing", {"thing": "x", "tenant_id": "TENANT_B"}, agent_id="A")
    assert r.status == "invalid_arguments"
    assert journal == []
    assert audit.events[0].reason == "invalid_arguments"


def test_non_dict_arguments_are_rejected(ctx):
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)))
    assert ex.execute(ctx, "do_thing", "tenant_id=TENANT_B", agent_id="A").status == "invalid_arguments"
    assert journal == []


def test_missing_resource_is_not_found_and_not_executed(ctx):
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)), resolved=None)
    r = ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="A")
    assert r.status == "not_found" and journal == []
    assert audit.events[0].decision == "DENY" and audit.events[0].reason == "resource_not_found"


def test_unknown_agent_is_denied(ctx, monkeypatch):
    monkeypatch.setattr(te.agents_repo, "get_agent", lambda *a, **k: None)
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)))
    r = ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="GHOST")
    assert r.status == "denied" and journal == []


def test_execution_failure_rolls_back_and_is_audited(ctx):
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)), raises=RuntimeError("db exploded: secret=abc"))
    r = ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="A")
    assert r.status == "error"
    assert "secret" not in r.message and "exploded" not in r.message     # safe error handling
    ctx.db.rollback.assert_called()
    assert audit.events[0].decision == "ALLOW" and audit.events[0].execution_status == "FAILED"


def test_human_approval_gate_parks_request_instead_of_executing(ctx, monkeypatch):
    monkeypatch.setattr(te.approvals_repo, "create", lambda *a, **k: uuid.UUID(int=7))
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",), require_human_approval=True))
    r = ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="A")
    assert r.status == "pending_approval" and r.approval_request_id == str(uuid.UUID(int=7))
    assert "execute" not in journal
    assert audit.events[0].decision == "PENDING" and audit.events[0].execution_status == "PENDING_APPROVAL"


def test_opa_input_is_built_from_trusted_sources_only(ctx):
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)))
    ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="A")
    payload = opa.payloads[0]
    assert payload["subject"]["id"] == str(ctx.principal.user_id)
    assert payload["subject"]["tenant_id"] == "TENANT_A"
    assert payload["subject"]["approval_limit"] == 10000.0
    assert payload["context"]["channel"] == "agent" and payload["context"]["approval_granted"] is False
    assert payload["agent"] == {"id": "A", "enabled": True, "tenant_id": "TENANT_A"}
    assert payload["tool"]["name"] == "do_thing"


def test_approval_grant_comes_from_the_database_only(ctx, monkeypatch):
    monkeypatch.setattr(te.approvals_repo, "find", lambda *a, **k: {"id": uuid.UUID(int=9)} if k.get("status") == "APPROVED" else None)
    monkeypatch.setattr(te.approvals_repo, "mark_executed", lambda *a, **k: True)
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)))
    ex.execute(ctx, "do_thing", {"thing": "x"}, agent_id="A")
    assert opa.payloads[0]["context"]["approval_granted"] is True


def test_api_channel_has_no_agent_object(ctx):
    ex, opa, audit, journal = make(Decision(True, ("allowed_by_policy",)))
    ex.execute(ctx, "do_thing", {"thing": "x"})
    assert opa.payloads[0]["context"]["channel"] == "api" and "agent" not in opa.payloads[0]
