"""The ONLY place in the backend that talks to OPA. Everything fails CLOSED:
OPA unreachable / timing out / returning anything unexpected => DENY."""
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.config import Settings

log = logging.getLogger("authz.opa")


@dataclass(frozen=True)
class Decision:
    allow: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
    require_human_approval: bool = False

    @property
    def reason(self) -> str:
        return ",".join(self.reasons) if self.reasons else "denied_by_default"


def deny(reason: str) -> Decision:
    return Decision(False, (reason,), False)


class OpaClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(
            base_url=settings.opa_url.rstrip("/"),
            headers={"Authorization": f"Bearer {settings.opa_token}"},  # service-to-service credential
            timeout=settings.opa_timeout_seconds,
            follow_redirects=False,
            transport=transport,
        )

    def _query(self, path: str, payload: dict[str, Any]) -> Any:
        resp = self._client.post(f"/v1/data/enterprise/{path}", json={"input": payload})
        resp.raise_for_status()
        return resp.json().get("result")

    def _decision(self, path: str, payload: dict[str, Any]) -> Decision:
        try:
            result = self._query(path, payload)
        except Exception as exc:  # network, timeout, 4xx/5xx, bad JSON: all deny
            log.error("OPA query failed path=%s error=%s", path, type(exc).__name__)
            return deny("opa_unavailable")
        if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
            return deny("opa_undefined_result")
        reasons = result.get("reasons")
        reasons_t = tuple(str(r) for r in reasons) if isinstance(reasons, list) else ()
        allow = result["allow"] is True
        gate = allow and result.get("require_human_approval") is True
        return Decision(allow, reasons_t, gate)

    # -- the four decision points ------------------------------------------------------------
    def decide_resource(self, subject: dict, action: str, resource: dict) -> Decision:
        """RBAC + ABAC for a resource (policy: enterprise.authz)."""
        return self._decision("authz/decision", {"subject": subject, "action": action, "resource": resource})

    def decide_agent(self, subject: dict, agent: dict) -> Decision:
        """May this user run this agent (policy: enterprise.agents)."""
        return self._decision("agents/decision", {"subject": subject, "agent": agent, "action": "execute"})

    def decide_tool(self, payload: dict[str, Any]) -> Decision:
        """Tool invocation: agent + tool + resource + business rules (policy: enterprise.tools)."""
        return self._decision("tools/decision", payload)

    def allowed_ids(self, subject: dict, action: str, resources: list[dict]) -> set[str]:
        """Row-level filter for collections. Fails closed: any problem => empty set."""
        if not resources:
            return set()
        try:
            result = self._query("authz/allowed_ids", {"subject": subject, "action": action, "resources": resources})
        except Exception as exc:
            log.error("OPA allowed_ids failed error=%s", type(exc).__name__)
            return set()
        return {str(i) for i in result} if isinstance(result, list) else set()

    def healthy(self) -> bool:
        try:
            return self._client.get("/health").status_code == 200
        except Exception:
            return False


_opa: OpaClient | None = None


def get_opa() -> OpaClient:
    """Overridable in tests via app.dependency_overrides[get_opa]."""
    global _opa
    if _opa is None:
        from app.core.config import get_settings

        _opa = OpaClient(get_settings())
    return _opa
