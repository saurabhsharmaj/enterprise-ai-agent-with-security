"""HTTP-level authentication behaviour. These requests are rejected BEFORE any database access."""
import pytest

from tests.conftest import auth, make_token, other_key_token

PROTECTED = [
    ("GET", "/api/me"), ("GET", "/api/agents"), ("GET", "/api/agents/FINANCE_AGENT"),
    ("POST", "/api/agents/FINANCE_AGENT/chat"), ("GET", "/api/invoices"), ("GET", "/api/invoices/INV-1001"),
    ("POST", "/api/invoices/INV-1001/approve"), ("POST", "/api/purchase-orders"), ("POST", "/api/authorization/check"),
    ("GET", "/api/users"), ("GET", "/api/roles"), ("GET", "/api/permissions"), ("GET", "/api/audit-logs"),
    ("GET", "/api/approvals"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_unauthenticated_request_rejected(client, method, path):
    r = client.request(method, path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")
    assert r.json()["detail"]["error"] == "missing_token"


def test_garbage_bearer_token_rejected(client):
    r = client.get("/api/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "invalid_token"


def test_token_signed_by_wrong_key_rejected(client):
    r = client.get("/api/me", headers={"Authorization": f"Bearer {other_key_token('alice')}"})
    assert r.status_code == 401


def test_expired_token_rejected(client):
    r = client.get("/api/me", headers=auth("alice", expires_in=-300))
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "token_expired"


def test_wrong_audience_rejected(client):
    r = client.get("/api/me", headers={"Authorization": f"Bearer {make_token('alice', aud=['account'])}"})
    assert r.status_code == 401


def test_basic_auth_scheme_is_not_accepted(client):
    r = client.get("/api/me", headers={"Authorization": "Basic YWxpY2U6YWxpY2U="})
    assert r.status_code == 401


def test_health_is_public_and_reveals_nothing(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_every_response_carries_correlation_id_and_security_headers(client):
    r = client.get("/api/health", headers={"X-Correlation-ID": "abcdef123456"})
    assert r.headers["x-correlation-id"] == "abcdef123456"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_malicious_correlation_id_is_replaced(client):
    r = client.get("/api/health", headers={"X-Correlation-ID": "x\r\nSet-Cookie: a=b"})
    assert "\n" not in r.headers["x-correlation-id"]
    assert r.headers["x-correlation-id"] != "x"


def test_cors_allows_only_configured_origin(client):
    ok = client.options("/api/me", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    evil = client.options("/api/me", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in evil.headers


def test_oversized_body_rejected(client):
    r = client.post("/api/agents/FINANCE_AGENT/chat", content=b"x" * 70_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
