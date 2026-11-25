#!/usr/bin/env python3
"""Generates keycloak/realm-export.json (the file Keycloak imports at start-up).

Run:  python3 keycloak/build_realm.py

Why a generator? The same client IDs, claim names and user UUIDs must match the backend
(JWT validation), the database seed and the OPA data. Keeping them in one script avoids drift.

DEVELOPMENT ONLY: the passwords below are demo credentials.
"""
import json
import pathlib

REALM = "enterprise-ai"
API_AUDIENCE = "enterprise-ai-api"
FRONTEND_CLIENT = "enterprise-ai-frontend"
SWAGGER_CLIENT = "enterprise-ai-swagger"
CLI_CLIENT = "enterprise-ai-cli"

# Fixed UUIDs => the JWT `sub` claim is stable and matches users.id in PostgreSQL (see app/seed.py).
USERS = [
    dict(id="11111111-1111-4111-8111-111111111111", username="alice", first="Alice", last="Anderson",
         role="ADMIN", department="IT", tenant="TENANT_A", password="Alice#Dev2026"),
    dict(id="22222222-2222-4222-8222-222222222222", username="bob", first="Bob", last="Brown",
         role="MANAGER", department="FINANCE", tenant="TENANT_A", password="Bob#Dev2026"),
    dict(id="33333333-3333-4333-8333-333333333333", username="charlie", first="Charlie", last="Clark",
         role="EMPLOYEE", department="FINANCE", tenant="TENANT_A", password="Charlie#Dev2026"),
    dict(id="44444444-4444-4444-8444-444444444444", username="david", first="David", last="Davis",
         role="MANAGER", department="FINANCE", tenant="TENANT_B", password="David#Dev2026"),
]


def attr_mapper(name, attribute):
    return {
        "name": name, "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {"user.attribute": attribute, "claim.name": name, "jsonType.label": "String",
                   "access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"},
    }


def claim_mappers():
    return [
        attr_mapper("tenant_id", "tenant_id"),
        attr_mapper("department", "department"),
        {   # flat top-level "roles": ["MANAGER", ...] (realm roles)
            "name": "roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "consentRequired": False,
            "config": {"claim.name": "roles", "multivalued": "true", "jsonType.label": "String",
                       "access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"},
        },
        {   # "groups": ["FINANCE"]
            "name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
            "consentRequired": False,
            "config": {"claim.name": "groups", "full.path": "false", "multivalued": "true",
                       "access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"},
        },
        {   # puts "enterprise-ai-api" into `aud` so the API can verify the token was minted FOR it
            "name": "api-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False,
            "config": {"included.custom.audience": API_AUDIENCE, "access.token.claim": "true",
                       "id.token.claim": "false"},
        },
    ]


DEFAULT_SCOPES = ["web-origins", "acr", "profile", "roles", "email"]


def public_client(client_id, name, redirect_uris, web_origins, *, standard_flow=True, direct_grants=False,
                  extra_attributes=None):
    attributes = {"pkce.code.challenge.method": "S256", "access.token.lifespan": "300"}
    attributes.update(extra_attributes or {})
    return {
        "clientId": client_id, "name": name, "enabled": True, "protocol": "openid-connect",
        "publicClient": True, "bearerOnly": False, "standardFlowEnabled": standard_flow,
        "implicitFlowEnabled": False, "directAccessGrantsEnabled": direct_grants,
        "serviceAccountsEnabled": False, "fullScopeAllowed": True,
        "redirectUris": redirect_uris, "webOrigins": web_origins, "attributes": attributes,
        "defaultClientScopes": DEFAULT_SCOPES, "protocolMappers": claim_mappers(),
    }


# Users may not edit tenant_id / department themselves: only admins can (declarative user profile).
USER_PROFILE = {
    "attributes": [
        {"name": "username", "displayName": "${username}",
         "validations": {"length": {"min": 3, "max": 255}, "username-prohibited-characters": {},
                         "up-username-not-idn-homograph": {}},
         "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False},
        {"name": "email", "displayName": "${email}",
         "validations": {"email": {}, "length": {"max": 255}},
         "required": {"roles": ["user"]},
         "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False},
        {"name": "firstName", "displayName": "${firstName}",
         "validations": {"length": {"max": 255}, "person-name-prohibited-characters": {}},
         "required": {"roles": ["user"]},
         "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False},
        {"name": "lastName", "displayName": "${lastName}",
         "validations": {"length": {"max": 255}, "person-name-prohibited-characters": {}},
         "required": {"roles": ["user"]},
         "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False},
        {"name": "tenant_id", "displayName": "Tenant",
         "validations": {"pattern": {"pattern": "^[A-Z0-9_]{1,64}$", "error-message": "Invalid tenant id"}},
         "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False},
        {"name": "department", "displayName": "Department",
         "validations": {"length": {"max": 64}},
         "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False},
    ],
}


def build():
    realm = {
        "realm": REALM,
        "displayName": "Enterprise AI",
        "enabled": True,
        "sslRequired": "none",              # DEV ONLY (plain http on localhost). Use "external"/"all" in prod.
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "editUsernameAllowed": False,
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
        "bruteForceProtected": True,
        "failureFactor": 5,
        "accessTokenLifespan": 300,          # 5 minutes: short-lived access tokens
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 36000,
        "revokeRefreshToken": True,          # refresh-token rotation
        "refreshTokenMaxReuse": 0,
        "defaultSignatureAlgorithm": "RS256",
        "eventsEnabled": True,
        "adminEventsEnabled": True,
        "roles": {"realm": [
            {"name": "ADMIN", "description": "Tenant administrator"},
            {"name": "MANAGER", "description": "Finance manager"},
            {"name": "EMPLOYEE", "description": "Regular employee"},
        ]},
        "groups": [{"name": "IT"}, {"name": "FINANCE"}],
        "clients": [
            {   # Resource server: it is only ever the AUDIENCE of tokens.
                "clientId": API_AUDIENCE, "name": "Enterprise AI API", "enabled": True,
                "bearerOnly": True, "publicClient": False, "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
            },
            public_client(FRONTEND_CLIENT, "Enterprise AI Frontend (React)",
                          ["http://localhost:3000/*"], ["http://localhost:3000"],
                          extra_attributes={"post.logout.redirect.uris": "http://localhost:3000/*"}),
            public_client(SWAGGER_CLIENT, "Swagger UI (dev)",
                          ["http://localhost:8000/docs/oauth2-redirect"], ["http://localhost:8000"]),
            public_client(CLI_CLIENT, "CLI / smoke tests (dev ONLY - password grant)",
                          [], [], standard_flow=False, direct_grants=True),
        ],
        "components": {
            "org.keycloak.userprofile.UserProfileProvider": [{
                "id": "6a0f5a4e-0f0c-4a54-9b0e-6c1f3f1d9a01",
                "providerId": "declarative-user-profile",
                "subComponents": {},
                "config": {"kc.user.profile.config": [json.dumps(USER_PROFILE)]},
            }]
        },
        "users": [
            {
                "id": u["id"], "username": u["username"], "enabled": True, "emailVerified": True,
                "firstName": u["first"], "lastName": u["last"],
                "email": f"{u['username']}@{u['tenant'].lower().replace('_', '-')}.example",
                "attributes": {"tenant_id": [u["tenant"]], "department": [u["department"]]},
                "credentials": [{"type": "password", "value": u["password"], "temporary": False}],
                "realmRoles": [u["role"]],
                "groups": [f"/{u['department']}"] if u["department"] in ("IT", "FINANCE") else [],
                "requiredActions": [],
            }
            for u in USERS
        ],
    }
    return realm


if __name__ == "__main__":
    out = pathlib.Path(__file__).with_name("realm-export.json")
    out.write_text(json.dumps(build(), indent=2) + "\n")
    print(f"wrote {out}")
