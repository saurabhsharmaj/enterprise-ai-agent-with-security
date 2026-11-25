"""JWT validation against Keycloak.

Checks performed on EVERY request (see TokenValidator.validate):
  * signature (RS256 only; `alg: none` / HS256 downgrade attacks are impossible) via Keycloak JWKS
  * issuer           == OIDC_ISSUER
  * audience         contains OIDC_AUDIENCE  (token was minted FOR this API)
  * expiry / iat     (small clock-skew leeway)
  * authorized party (`azp`) is one of OIDC_ALLOWED_CLIENTS
  * required claims: sub (UUID), preferred_username, tenant_id (well-formed)
Identity is ONLY ever taken from this validated token, never from request parameters.
"""
import re
import uuid
from dataclasses import dataclass
from typing import Any, Callable

import jwt
from jwt import PyJWKClient

from app.core.config import Settings

ALLOWED_ALGORITHMS = ["RS256"]
TENANT_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
KNOWN_ROLES = frozenset({"ADMIN", "MANAGER", "EMPLOYEE"})


class AuthError(Exception):
    """Authentication failed. The message is safe to return to the client (no token content)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TokenClaims:
    user_id: uuid.UUID
    username: str
    tenant_id: str
    roles: tuple[str, ...]
    groups: tuple[str, ...]
    department: str | None
    email: str | None
    client_id: str
    expires_at: int


KeyResolver = Callable[[str], Any]


class TokenValidator:
    def __init__(self, settings: Settings, key_resolver: KeyResolver | None = None):
        self._settings = settings
        if key_resolver is None:
            client = PyJWKClient(settings.oidc_jwks_url, cache_keys=True, lifespan=300, timeout=5)
            key_resolver = lambda token: client.get_signing_key_from_jwt(token).key  # noqa: E731
        self._resolve_key = key_resolver

    def validate(self, token: str) -> TokenClaims:
        if not token or len(token) > 8192:
            raise AuthError("invalid_token")
        try:
            key = self._resolve_key(token)
            claims = jwt.decode(
                token,
                key=key,
                algorithms=ALLOWED_ALGORITHMS,
                audience=self._settings.oidc_audience,
                issuer=self._settings.oidc_issuer,
                leeway=self._settings.oidc_leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            raise AuthError("token_expired") from None
        except (jwt.PyJWTError, Exception):  # includes JWKS fetch problems: fail closed
            raise AuthError("invalid_token") from None
        return self._extract(claims)

    def _extract(self, claims: dict[str, Any]) -> TokenClaims:
        azp = claims.get("azp")
        if azp not in self._settings.allowed_clients:
            raise AuthError("client_not_authorized")
        try:
            user_id = uuid.UUID(str(claims["sub"]))
        except (KeyError, ValueError):
            raise AuthError("invalid_token") from None

        username = claims.get("preferred_username")
        tenant_id = claims.get("tenant_id")
        if not isinstance(username, str) or not username:
            raise AuthError("invalid_token")
        if not isinstance(tenant_id, str) or not TENANT_RE.match(tenant_id):
            raise AuthError("missing_tenant")

        raw_roles = claims.get("roles") or []
        if not isinstance(raw_roles, list):
            raise AuthError("invalid_token")
        roles = tuple(sorted({r for r in raw_roles if isinstance(r, str) and r in KNOWN_ROLES}))
        groups_raw = claims.get("groups") or []
        groups = tuple(sorted({g for g in groups_raw if isinstance(g, str)})) if isinstance(groups_raw, list) else ()
        dept = claims.get("department")
        email = claims.get("email")
        return TokenClaims(
            user_id=user_id,
            username=username,
            tenant_id=tenant_id,
            roles=roles,
            groups=groups,
            department=dept if isinstance(dept, str) else None,
            email=email if isinstance(email, str) else None,
            client_id=azp,
            expires_at=int(claims["exp"]),
        )
