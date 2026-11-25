"""Shared test setup.

* A throw-away RSA key signs test tokens; the API's TokenValidator is pointed at the matching public
  key, so the REAL validation code (signature, issuer, audience, expiry, azp) runs in every test.
* tests/unit        : need nothing external.
* tests/integration : need the real PostgreSQL + OPA (run via `docker compose --profile test run --rm tests`).
"""
import os
import time
import uuid

# Settings must exist before `app` is imported. Compose provides the real values for integration runs.
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://eai_app:unused@localhost:5432/enterprise_ai")
os.environ.setdefault("OPA_URL", "http://localhost:8181")
os.environ.setdefault("OPA_TOKEN", "t" * 48)
os.environ.setdefault("OIDC_ISSUER", "http://localhost:8080/realms/enterprise-ai")
os.environ.setdefault("OIDC_JWKS_URL", "http://localhost:8080/realms/enterprise-ai/protocol/openid-connect/certs")
os.environ.setdefault("OIDC_AUDIENCE", "enterprise-ai-api")
os.environ.setdefault("OIDC_ALLOWED_CLIENTS", "enterprise-ai-frontend,enterprise-ai-swagger,enterprise-ai-cli")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:3000")

import jwt  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.jwt import TokenValidator  # noqa: E402
from app.core.security import get_validator, rate_limiter_state  # noqa: E402

SETTINGS = get_settings()

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = _PRIVATE_KEY.public_key()

# Same ids as keycloak/build_realm.py and app/seed.py (checked by tests/unit/test_realm_consistency.py)
USERS = {
    "alice":   dict(id="11111111-1111-4111-8111-111111111111", tenant="TENANT_A", roles=["ADMIN"],    groups=["IT"],      dept="IT"),
    "bob":     dict(id="22222222-2222-4222-8222-222222222222", tenant="TENANT_A", roles=["MANAGER"],  groups=["FINANCE"], dept="FINANCE"),
    "charlie": dict(id="33333333-3333-4333-8333-333333333333", tenant="TENANT_A", roles=["EMPLOYEE"], groups=["FINANCE"], dept="FINANCE"),
    "david":   dict(id="44444444-4444-4444-8444-444444444444", tenant="TENANT_B", roles=["MANAGER"],  groups=["FINANCE"], dept="FINANCE"),
}


def make_token(username: str = "bob", *, expires_in: int = 300, key=None, drop: tuple[str, ...] = (), **overrides) -> str:
    u = USERS[username]
    now = int(time.time())
    claims = {
        "iss": SETTINGS.oidc_issuer, "aud": [SETTINGS.oidc_audience, "account"], "azp": "enterprise-ai-frontend",
        "sub": u["id"], "preferred_username": username, "tenant_id": u["tenant"], "roles": u["roles"],
        "groups": u["groups"], "department": u["dept"], "email": f"{username}@example.test",
        "iat": now, "exp": now + expires_in,
    }
    claims.update(overrides)
    for k in drop:
        claims.pop(k, None)
    return jwt.encode(claims, key or _PRIVATE_KEY, algorithm="RS256", headers={"kid": "test-key"})


def other_key_token(username: str = "bob", **kw) -> str:
    return make_token(username, key=_OTHER_KEY, **kw)


def auth(username: str, **kw) -> dict:
    return {"Authorization": f"Bearer {make_token(username, **kw)}"}


@pytest.fixture(scope="session")
def validator() -> TokenValidator:
    return TokenValidator(SETTINGS, key_resolver=lambda token: PUBLIC_KEY)


@pytest.fixture()
def client(validator):
    from app.main import app

    app.dependency_overrides[get_validator] = lambda: validator
    rate_limiter_state.reset()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ----------------------------------------------------------------------------- integration gating
def _integration_available() -> bool:
    if not os.environ.get("DATABASE_ADMIN_URL"):
        return False
    try:
        from sqlalchemy import text

        from app.core.db import get_engine

        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
        import httpx

        return httpx.get(f"{SETTINGS.opa_url}/health", timeout=2).status_code == 200
    except Exception:
        return False


INTEGRATION = _integration_available()


def pytest_collection_modifyitems(config, items):
    if INTEGRATION:
        return
    if os.environ.get("REQUIRE_INTEGRATION") == "1":
        raise pytest.UsageError("REQUIRE_INTEGRATION=1 but PostgreSQL/OPA are not reachable")
    skip = pytest.mark.skip(reason="integration services not available (use docker compose --profile test)")
    for item in items:
        if "integration" in item.nodeid.replace("\\", "/").split("/"):
            item.add_marker(skip)


@pytest.fixture()
def admin_sql():
    """Runs SQL as the database OWNER (bypasses RLS) to inspect/prepare state independently of the API."""
    from sqlalchemy import create_engine, text

    engine = create_engine(os.environ["DATABASE_ADMIN_URL"])

    def run(sql: str, **params):
        with engine.begin() as c:
            result = c.execute(text(sql), params)
            return [dict(r) for r in result.mappings().all()] if result.returns_rows else result.rowcount

    yield run
    engine.dispose()


@pytest.fixture()
def cid() -> str:
    """A unique correlation id so a test can find exactly its own audit rows."""
    return "test-" + uuid.uuid4().hex[:16]
