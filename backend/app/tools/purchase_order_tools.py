"""create_purchase_order. The resource OPA evaluates is built from the validated arguments plus the
TRUSTED principal (tenant, department, owner): the caller cannot choose a tenant or department."""
from app.repositories import purchase_orders as repo
from app.schemas.tool_args import CreatePurchaseOrderArgs
from app.tools.base import Resolved, ToolContext, ToolSpec


def resolve_create(ctx: ToolContext, args: CreatePurchaseOrderArgs) -> Resolved:
    p = ctx.principal
    return Resolved(resource={
        "type": "purchase_order", "id": "NEW", "tenant_id": p.tenant_id, "department": p.department,
        "owner_id": str(p.user_id), "status": "SUBMITTED", "amount": float(args.amount),
    })


def create_purchase_order(ctx: ToolContext, args: CreatePurchaseOrderArgs, resolved: Resolved) -> dict:
    p = ctx.principal
    po = repo.create(ctx.db, p.tenant_id, vendor=args.vendor, description=args.description, amount=args.amount,
                     currency=args.currency, department=p.department, created_by=p.user_id)
    return {"purchase_order": po}


CREATE_PURCHASE_ORDER = ToolSpec("create_purchase_order",
                                 "Create a purchase order (amount must be within the caller's approval limit)",
                                 "purchase_order", "create", CreatePurchaseOrderArgs,
                                 resolve_create, create_purchase_order)
