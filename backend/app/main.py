import logging
import re
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.mcp_http import router as mcp_router
from app.api.router import api_router
from app.core.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("app")

_CORRELATION_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")
MAX_BODY_BYTES = 64 * 1024


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Enterprise AI Agent Auth Platform",
        version="1.0.0",
        description=("Keycloak (OIDC) authentication, OPA authorisation, deny-by-default. Every agent tool call is "
                     "authorised by OPA immediately before execution and audited. Use **Authorize** (client "
                     "`enterprise-ai-swagger`, PKCE) and log in as alice / bob / charlie / david."),
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
        swagger_ui_init_oauth={"clientId": "enterprise-ai-swagger", "usePkceWithAuthorizationCodeGrant": True,
                               "scopes": "openid profile"},
    )

    # Explicit origins only; no credentials/cookies are used (Bearer tokens), so wildcard is never needed.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Correlation-ID", "MCP-Protocol-Version"],
        expose_headers=["X-Correlation-ID", "Retry-After"],
        allow_credentials=False,
        max_age=600,
    )

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        header = request.headers.get("x-correlation-id", "")
        request.state.correlation_id = header if _CORRELATION_RE.match(header) else str(uuid.uuid4())
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            response = JSONResponse(status_code=413, content={"detail": {"error": "payload_too_large"}})
        else:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Never leak internals. Details go to the server log (which never receives tokens).
        cid = getattr(request.state, "correlation_id", "-")
        log.error("unhandled error correlation_id=%s type=%s", cid, type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": {"error": "internal_error", "correlation_id": cid}})

    app.include_router(api_router)
    app.include_router(mcp_router)
    return app


app = create_app()
