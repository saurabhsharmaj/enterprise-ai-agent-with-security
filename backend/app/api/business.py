"""Business REST endpoints. They do NOT implement their own checks: each one calls the same secure
ToolExecutor the agent uses (channel "api"), so REST and agent paths share one enforcement point."""
from typing import Literal

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import JSONResponse

from app.agents.tool_executor import ToolExecutor
from app.api.deps import get_executor, tool_response
from app.core.security import RequestContext, get_request_context, rate_limit
from app.schemas.tool_args import CreatePurchaseOrderArgs

router = APIRouter(tags=["business"])
InvoiceIdPath = Path(pattern=r"^INV-\d{1,12}$", description="e.g. INV-1001")


@router.get("/invoices", summary="Search invoices you are allowed to see")
def list_invoices(status: Literal["PENDING", "APPROVED", "REJECTED", "PAID"] | None = None, mine: bool = False,
                  q: str | None = Query(default=None, max_length=100), limit: int = Query(default=20, ge=1, le=50),
                  ctx: RequestContext = Depends(get_request_context),
                  executor: ToolExecutor = Depends(get_executor)) -> JSONResponse:
    args = {"status": status, "mine": mine, "query": q, "limit": limit}
    return tool_response(executor.execute(ctx, "search_invoices", {k: v for k, v in args.items() if v is not None}),
                         ctx.correlation_id)


@router.get("/invoices/{invoice_id}", summary="Read one invoice")
def get_invoice(invoice_id: str = InvoiceIdPath, ctx: RequestContext = Depends(get_request_context),
                executor: ToolExecutor = Depends(get_executor)) -> JSONResponse:
    return tool_response(executor.execute(ctx, "read_invoice", {"invoice_id": invoice_id}), ctx.correlation_id)


@router.post("/invoices/{invoice_id}/approve", summary="Approve a pending invoice (limits + rules enforced by OPA)",
             dependencies=[Depends(rate_limit("sensitive", "rate_limit_sensitive_per_minute"))])
def approve_invoice(invoice_id: str = InvoiceIdPath, ctx: RequestContext = Depends(get_request_context),
                    executor: ToolExecutor = Depends(get_executor)) -> JSONResponse:
    return tool_response(executor.execute(ctx, "approve_invoice", {"invoice_id": invoice_id}), ctx.correlation_id)


@router.post("/purchase-orders", summary="Create a purchase order (within your approval limit)", status_code=201,
             dependencies=[Depends(rate_limit("sensitive", "rate_limit_sensitive_per_minute"))])
def create_purchase_order(body: CreatePurchaseOrderArgs, ctx: RequestContext = Depends(get_request_context),
                          executor: ToolExecutor = Depends(get_executor)) -> JSONResponse:
    # The body model forbids extra fields, so tenant_id / department / owner can never be supplied.
    result = executor.execute(ctx, "create_purchase_order", body.model_dump(mode="json"))
    return tool_response(result, ctx.correlation_id, success_status=201)
