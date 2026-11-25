from app.repositories import documents as repo
from app.schemas.tool_args import SearchDocumentsArgs
from app.tools.base import Resolved, ToolContext, ToolSpec, collection_resource


def document_resource(row: dict) -> dict:
    return {
        "type": "document", "id": str(row["id"]), "tenant_id": row["tenant_id"],
        "department": row["department"], "owner_id": str(row["owner_id"]),
        "classification": row["classification"],
    }


def resolve_search(ctx: ToolContext, args: SearchDocumentsArgs) -> Resolved:
    return Resolved(resource=collection_resource(ctx, "document"))


def search_documents(ctx: ToolContext, args: SearchDocumentsArgs, resolved: Resolved) -> dict:
    p = ctx.principal
    candidates = repo.search(ctx.db, p.tenant_id, args.query)
    allowed = ctx.opa.allowed_ids(p.opa_subject(), "read", [document_resource(r) for r in candidates])
    visible = [r for r in candidates if str(r["id"]) in allowed][: args.limit]
    return {"count": len(visible), "documents": [
        {"id": str(r["id"]), "title": r["title"], "department": r["department"],
         "classification": r["classification"], "snippet": r["body"][:200]} for r in visible]}


SEARCH_DOCUMENTS = ToolSpec("search_documents", "Full-text search over documents visible to the caller",
                            "document", "search", SearchDocumentsArgs, resolve_search, search_documents)
