import pytest
from pydantic import ValidationError

from app.schemas.tool_args import (ApproveInvoiceArgs, CreatePurchaseOrderArgs, ReadInvoiceArgs, SearchDocumentsArgs,
                                   SearchInvoicesArgs)


@pytest.mark.parametrize("model,payload", [
    (ReadInvoiceArgs, {"invoice_id": "INV-1001", "tenant_id": "TENANT_B"}),
    (ApproveInvoiceArgs, {"invoice_id": "INV-1001", "user_id": "x"}),
    (ApproveInvoiceArgs, {"invoice_id": "INV-1001", "roles": ["ADMIN"]}),
    (CreatePurchaseOrderArgs, {"amount": "10", "tenant_id": "TENANT_B"}),
    (CreatePurchaseOrderArgs, {"amount": "10", "approval_limit": 999999}),
    (SearchInvoicesArgs, {"owner_id": "x"}),
])
def test_smuggled_fields_are_rejected(model, payload):
    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize("bad", ["inv-1", "INV-", "INV-1; DROP TABLE invoices", "../INV-1", "INV-12345678901234", "", "INV-1001\nINV-1002"])
def test_invoice_id_format_is_enforced(bad):
    with pytest.raises(ValidationError):
        ReadInvoiceArgs.model_validate({"invoice_id": bad})


@pytest.mark.parametrize("amount", ["0", "-5", "10000001", "12.345", "abc", None])
def test_purchase_order_amount_bounds(amount):
    with pytest.raises(ValidationError):
        CreatePurchaseOrderArgs.model_validate({"amount": amount})


def test_valid_purchase_order_defaults():
    a = CreatePurchaseOrderArgs.model_validate({"amount": "5000"})
    assert a.vendor == "General Vendor" and a.currency == "USD"


def test_limits_and_enums():
    with pytest.raises(ValidationError):
        SearchInvoicesArgs.model_validate({"limit": 1000})
    with pytest.raises(ValidationError):
        SearchInvoicesArgs.model_validate({"status": "DELETED"})
    with pytest.raises(ValidationError):
        SearchDocumentsArgs.model_validate({"query": ""})
    with pytest.raises(ValidationError):
        SearchDocumentsArgs.model_validate({"query": "x" * 101})
