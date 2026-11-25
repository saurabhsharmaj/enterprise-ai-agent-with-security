from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.authorization.opa_client import OpaClient, get_opa
from app.core.db import get_engine
from app.core.security import RequestContext, get_request_context
from app.repositories import admin as admin_repo

router = APIRouter()


@router.get("/health", tags=["system"], summary="Liveness probe (public, reveals nothing)")
def health() -> dict:
    return {"status": "ok"}


@router.get("/health/ready", tags=["system"], summary="Readiness probe: database + policy engine")
def ready(opa: OpaClient = Depends(get_opa)) -> dict:
    db_ok = True
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    opa_ok = opa.healthy()
    return {"status": "ok" if db_ok and opa_ok else "degraded", "database": db_ok, "policy_engine": opa_ok}


@router.get("/me", tags=["auth"], summary="Who am I? (derived from the validated token + database)")
def me(ctx: RequestContext = Depends(get_request_context)) -> dict:
    p = ctx.principal
    permissions = admin_repo.permissions_for_roles(ctx.db, list(p.roles))
    return {
        "id": str(p.user_id), "username": p.username, "email": p.email, "tenant_id": p.tenant_id,
        "roles": list(p.roles), "groups": list(p.groups), "department": p.department,
        "approval_limit": p.approval_limit, "token_expires_at": p.token_expires_at,
        # UI hints only. The backend re-checks every action through OPA.
        "permissions": permissions,
    }
