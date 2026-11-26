"""Knowledge-base endpoints: list visible documents, add a document (chunked + embedded for RAG)."""
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StringConstraints

from app.api.deps import get_authz
from app.authorization.opa_client import OpaClient, get_opa
from app.core.security import RequestContext, get_request_context, rate_limit
from app.guardrails import Guardrails
from app.core.config import get_settings
from app.rag import repository as repo
from app.rag.service import ingest_document
from app.services.authorization_service import AuthorizationService
from app.tools.document_tools import document_resource

router = APIRouter(prefix="/documents", tags=["documents"])


class DocumentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=200)]
    body: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=20000)]
    department: Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Z_]{2,32}$")] | None = None
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] = "INTERNAL"


def _collection(ctx: RequestContext) -> dict:
    return {"type": "document", "id": "*", "tenant_id": ctx.principal.tenant_id, "scope": "collection"}


@router.get("", summary="Documents you may read (OPA row filter)")
def list_documents(ctx: RequestContext = Depends(get_request_context), authz: AuthorizationService = Depends(get_authz),
                   opa: OpaClient = Depends(get_opa)) -> dict:
    p = ctx.principal
    authz.require(ctx, "search", _collection(ctx))
    rows = repo.list_documents(ctx.db, p.tenant_id)
    allowed = opa.allowed_ids(p.opa_subject(), "read", [document_resource(r) for r in rows])
    return {"documents": [{**r, "id": str(r["id"]), "owner_id": str(r["owner_id"])} for r in rows if str(r["id"]) in allowed]}


@router.post("", status_code=201, summary="Add a document to the knowledge base (manager/admin)",
             dependencies=[Depends(rate_limit("sensitive", "rate_limit_sensitive_per_minute"))])
def create_document(body: DocumentCreate, ctx: RequestContext = Depends(get_request_context),
                    authz: AuthorizationService = Depends(get_authz)) -> dict:
    p = ctx.principal
    department = body.department or p.department
    if not department:
        raise HTTPException(422, detail={"error": "department_required"})
    # ALL authorisation (permission, tenant, department, classification vs. clearance) is decided by OPA from the
    # attributes of the document being created.
    authz.require(ctx, "create", {"type": "document", "id": "NEW", "tenant_id": p.tenant_id, "department": department,
                                  "owner_id": str(p.user_id), "classification": body.classification})
    flags = Guardrails(get_settings().guardrail_mode).scan_untrusted_text(body.body)
    if flags and get_settings().guardrail_mode == "block":
        raise HTTPException(422, detail={"error": "guardrail_blocked", "reasons": flags,
                                         "message": "The document contains instruction-like text and was rejected."})
    doc_id = repo.insert_document(ctx.db, p.tenant_id, body.title, body.body, department, body.classification,
                                  str(p.user_id))
    chunks = ingest_document(ctx.db, p.tenant_id, doc_id, body.body)
    ctx.db.commit()
    return {"id": doc_id, "title": body.title, "department": department, "classification": body.classification,
            "chunks": chunks, "guardrail_flags": flags}
