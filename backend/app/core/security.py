"""Authentication dependency + trusted user context.

Flow per request:  Bearer token -> TokenValidator (signature/iss/aud/exp/azp) -> tenant-pinned DB
session -> load the user row (must exist and be active; row-level security hides other tenants) ->
`Principal`. Roles come from the verified token; department and approval limit come from the
database. Nothing identity-related is ever read from request bodies, query strings or headers
other than Authorization.
"""
import re
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Iterator

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.db import new_tenant_session
from app.core.jwt import AuthError, TokenClaims, TokenValidator

_CORRELATION_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")

# auto_error=False: we return our own consistent 401 (and Swagger gets its Authorize button).
# The issuer URL is the browser-facing Keycloak URL (http://localhost:8080/realms/enterprise-ai).
_issuer = get_settings().oidc_issuer.rstrip("/")
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{_issuer}/protocol/openid-connect/auth",
    tokenUrl=f"{_issuer}/protocol/openid-connect/token",
    auto_error=False,
)

_validator: TokenValidator | None = None


def get_validator() -> TokenValidator:
    """Overridable in tests via app.dependency_overrides[get_validator]."""
    global _validator
    if _validator is None:
        _validator = TokenValidator(get_settings())
    return _validator


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    username: str
    tenant_id: str
    roles: tuple[str, ...]
    groups: tuple[str, ...]
    department: str
    approval_limit: float
    email: str | None
    token_expires_at: int

    @property
    def is_admin(self) -> bool:
        return "ADMIN" in self.roles

    def opa_subject(self) -> dict:
        """The `input.subject` document sent to OPA. Built here, from trusted sources only."""
        return {
            "id": str(self.user_id),
            "username": self.username,
            "tenant_id": self.tenant_id,
            "roles": list(self.roles),
            "department": self.department,
            "approval_limit": self.approval_limit,
            "groups": list(self.groups),
        }


@dataclass
class RequestContext:
    principal: Principal
    db: Session
    correlation_id: str
    extras: dict = field(default_factory=dict)


def _unauthorized(code: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": code},
        headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{code}"'},
    )


def get_correlation_id(request: Request) -> str:
    cid = getattr(request.state, "correlation_id", None)
    if cid:
        return cid
    header = request.headers.get("x-correlation-id", "")
    return header if _CORRELATION_RE.match(header) else str(uuid.uuid4())


def get_request_context(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    validator: TokenValidator = Depends(get_validator),
) -> Iterator[RequestContext]:
    if not token:
        raise _unauthorized("missing_token")
    try:
        claims: TokenClaims = validator.validate(token)
    except AuthError as exc:
        raise _unauthorized(exc.code) from None

    db = new_tenant_session(claims.tenant_id)
    try:
        row = db.execute(
            text("SELECT id, username, department, approval_limit, is_active, email "
                 "FROM users WHERE id = :id AND tenant_id = :t"),
            {"id": claims.user_id, "t": claims.tenant_id},
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=403, detail={"error": "user_not_provisioned"})
        if not row["is_active"]:
            raise HTTPException(status_code=403, detail={"error": "user_disabled"})
        principal = Principal(
            user_id=claims.user_id,
            username=claims.username,
            tenant_id=claims.tenant_id,
            roles=claims.roles,
            groups=claims.groups,
            department=row["department"],
            approval_limit=float(row["approval_limit"]),
            email=row["email"] or claims.email,
            token_expires_at=claims.expires_at,
        )
        db.rollback()  # end the read-only auth transaction; handlers open their own
        ctx = RequestContext(principal=principal, db=db, correlation_id=get_correlation_id(request))
        request.state.principal = principal
        yield ctx
    finally:
        db.rollback()
        db.close()


# ------------------------------------------------------------------------------------------------
# Rate limiting (sliding window, per user + bucket). In-memory: per process. Use Redis in production.
# ------------------------------------------------------------------------------------------------
class _SlidingWindow:
    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def hit(self, key: tuple[str, str], limit: int, window: float) -> float | None:
        """Returns None if allowed, else seconds until the next slot frees up."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] >= window:
                q.popleft()
            if len(q) >= limit:
                return window - (now - q[0])
            q.append(now)
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter_state = _SlidingWindow()


def rate_limit(bucket: str, per_minute_attr: str):
    """Dependency factory: `Depends(rate_limit("chat", "rate_limit_chat_per_minute"))`."""

    def dependency(ctx: RequestContext = Depends(get_request_context),
                   settings: Settings = Depends(get_settings)) -> None:
        limit = getattr(settings, per_minute_attr)
        wait = rate_limiter_state.hit((str(ctx.principal.user_id), bucket), limit, 60.0)
        if wait is not None:
            raise HTTPException(status_code=429, detail={"error": "rate_limited"},
                                headers={"Retry-After": str(int(wait) + 1)})

    return dependency
