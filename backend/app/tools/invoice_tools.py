"""Invoice tools: search_invoices, read_invoice, approve_invoice.

Each tool has two independent functions:
  resolve_*  - loads the TARGET resource (tenant-scoped) and describes it for OPA;
  *_invoice  - the business action, executed only after the executor got an ALLOW from OPA.
No tool decides authorisation itself.
"""
from app.repositories import invoices as repo
from app.schemas.tool_args import ApproveInvoiceArgs, ReadInvoiceArgs, SearchInvoicesArgs
from app.tools.base import Resolved, ToolConflict, ToolContext, ToolSpec, collection_resource


def invoice_resource(row: dict) -> dict:
    """OPA input.resource for an invoice (attributes come from the database)."""
    return {
        "type": "invoice",
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "department": row["department"],
        "owner_id": str(row["owner_id"]),
        "status": row["status"],
        "classification": row["classification"],
        "amount": float(row["amount"]),
    }


def _view(row: dict) -> dict:
    return {
        "id": row["id"], "vendor": row["vendor"], "description": row["description"],
        "amount": row["amount"], "currency": row["currency"], "status": row["status"],
        "department": row["department"], "classification": row["classification"],
        "owner": row["owner_username"], "approved_at": row["approved_at"],
    }


# ---------------------------------------------------------------- search_invoices
def resolve_search(ctx: ToolContext, args: SearchInvoicesArgs) -> Resolved:
    return Resolved(resource=collection_resource(ctx, "invoice"))


def search_invoices(ctx: ToolContext, args: SearchInvoicesArgs, resolved: Resolved) -> dict:
    p = ctx.principal
    candidates = repo.search(ctx.db, p.tenant_id, status=args.status,
                             owner_id=p.user_id if args.mine else None, query=args.query)
    # Collection access was authorised by OPA. Each ROW is then filtered by the same policy
    # (department, classification, ownership), so a search can never leak rows a read would deny.
    allowed = ctx.opa.allowed_ids(p.opa_subject(), "read", [invoice_resource(r) for r in candidates])
    visible = [r for r in candidates if r["id"] in allowed][: args.limit]
    return {"count": len(visible), "invoices": [_view(r) for r in visible]}


# ---------------------------------------------------------------- read_invoice
def resolve_read(ctx: ToolContext, args: ReadInvoiceArgs) -> Resolved | None:
    row = repo.get(ctx.db, ctx.principal.tenant_id, args.invoice_id)   # tenant-scoped => no IDOR
    return Resolved(resource=invoice_resource(row), record=row) if row else None


def read_invoice(ctx: ToolContext, args: ReadInvoiceArgs, resolved: Resolved) -> dict:
    return {"invoice": _view(resolved.record)}


# ---------------------------------------------------------------- approve_invoice
def resolve_approve(ctx: ToolContext, args: ApproveInvoiceArgs) -> Resolved | None:
    row = repo.get(ctx.db, ctx.principal.tenant_id, args.invoice_id)
    return Resolved(resource=invoice_resource(row), record=row) if row else None


def approve_invoice(ctx: ToolContext, args: ApproveInvoiceArgs, resolved: Resolved) -> dict:
    updated = repo.approve_atomic(ctx.db, ctx.principal.tenant_id, args.invoice_id, ctx.principal.user_id,
                                  expected_amount=resolved.record["amount"])
    if updated is None:
        # Someone else approved it, or it changed, between the OPA decision and now.
        raise ToolConflict("invoice_changed_concurrently")
    return {"invoice_id": updated["id"], "status": updated["status"], "approved_by": ctx.principal.username,
            "approved_at": updated["approved_at"]}


SEARCH_INVOICES = ToolSpec("search_invoices", "Search invoices visible to the caller (filters: status, mine, query)",
                           "invoice", "search", SearchInvoicesArgs, resolve_search, search_invoices)
READ_INVOICE = ToolSpec("read_invoice", "Read one invoice by id (e.g. INV-1001)",
                        "invoice", "read", ReadInvoiceArgs, resolve_read, read_invoice)
APPROVE_INVOICE = ToolSpec("approve_invoice", "Approve a pending invoice within the caller's approval limit",
                           "invoice", "approve", ApproveInvoiceArgs, resolve_approve, approve_invoice)
