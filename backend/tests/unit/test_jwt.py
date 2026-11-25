"""TokenValidator: signature, issuer, audience, expiry, authorised client, claim extraction."""
import base64
import hashlib
import hmac
import json
import time
import uuid

import pytest

from app.core.jwt import AuthError
from tests.conftest import SETTINGS, USERS, make_token, other_key_token


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_valid_token_is_accepted_and_claims_extracted(validator):
    claims = validator.validate(make_token("bob"))
    assert claims.user_id == uuid.UUID(USERS["bob"]["id"])
    assert claims.username == "bob"
    assert claims.tenant_id == "TENANT_A"
    assert claims.roles == ("MANAGER",)
    assert claims.groups == ("FINANCE",)


def test_expired_token_rejected(validator):
    with pytest.raises(AuthError) as e:
        validator.validate(make_token("bob", expires_in=-120))
    assert e.value.code == "token_expired"


def test_token_signed_with_another_key_rejected(validator):
    with pytest.raises(AuthError) as e:
        validator.validate(other_key_token("bob"))
    assert e.value.code == "invalid_token"


def test_wrong_issuer_rejected(validator):
    with pytest.raises(AuthError):
        validator.validate(make_token("bob", iss="http://evil.example/realms/enterprise-ai"))


def test_wrong_audience_rejected(validator):
    with pytest.raises(AuthError):
        validator.validate(make_token("bob", aud=["account"]))


def test_missing_audience_rejected(validator):
    with pytest.raises(AuthError):
        validator.validate(make_token("bob", drop=("aud",)))


def test_unauthorized_client_rejected(validator):
    with pytest.raises(AuthError) as e:
        validator.validate(make_token("bob", azp="some-other-app"))
    assert e.value.code == "client_not_authorized"


def test_missing_azp_rejected(validator):
    with pytest.raises(AuthError):
        validator.validate(make_token("bob", drop=("azp",)))


def test_missing_expiry_rejected(validator):
    with pytest.raises(AuthError):
        validator.validate(make_token("bob", drop=("exp",)))


def test_missing_or_malformed_tenant_rejected(validator):
    with pytest.raises(AuthError) as e:
        validator.validate(make_token("bob", drop=("tenant_id",)))
    assert e.value.code == "missing_tenant"
    with pytest.raises(AuthError):
        validator.validate(make_token("bob", tenant_id="tenant a; DROP TABLE"))


def test_non_uuid_subject_rejected(validator):
    with pytest.raises(AuthError):
        validator.validate(make_token("bob", sub="not-a-uuid"))


def test_unknown_roles_are_dropped(validator):
    claims = validator.validate(make_token("bob", roles=["MANAGER", "SUPERUSER", "ADMIN_FAKE", 7]))
    assert claims.roles == ("MANAGER",)


def test_alg_none_rejected(validator):
    header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"iss": SETTINGS.oidc_issuer, "aud": SETTINGS.oidc_audience, "azp": "enterprise-ai-frontend",
                            "sub": USERS["alice"]["id"], "preferred_username": "alice", "tenant_id": "TENANT_A",
                            "roles": ["ADMIN"], "iat": int(time.time()), "exp": int(time.time()) + 300}).encode())
    with pytest.raises(AuthError):
        validator.validate(f"{header}.{body}.")


def test_hs256_key_confusion_rejected(validator):
    """Classic attack: sign with HMAC using the public key as the secret."""
    from cryptography.hazmat.primitives import serialization

    from tests.conftest import PUBLIC_KEY

    pem = PUBLIC_KEY.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"iss": SETTINGS.oidc_issuer, "aud": SETTINGS.oidc_audience, "azp": "enterprise-ai-frontend",
                            "sub": USERS["alice"]["id"], "preferred_username": "alice", "tenant_id": "TENANT_A",
                            "roles": ["ADMIN"], "iat": int(time.time()), "exp": int(time.time()) + 300}).encode())
    sig = _b64(hmac.new(pem, f"{header}.{body}".encode(), hashlib.sha256).digest())
    with pytest.raises(AuthError):
        validator.validate(f"{header}.{body}.{sig}")


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "x" * 9000])
def test_garbage_rejected(validator, garbage):
    with pytest.raises(AuthError):
        validator.validate(garbage)


def test_jwks_failure_fails_closed():
    from app.core.jwt import TokenValidator

    def broken(_token):
        raise ConnectionError("keycloak down")

    with pytest.raises(AuthError) as e:
        TokenValidator(SETTINGS, key_resolver=broken).validate(make_token("bob"))
    assert e.value.code == "invalid_token"
