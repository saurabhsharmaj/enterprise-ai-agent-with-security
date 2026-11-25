"""Strict argument models for every tool. `extra="forbid"` means an LLM (or attacker) cannot smuggle
extra fields such as tenant_id / user_id / roles: validation fails and the call is rejected."""
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

InvoiceId = Annotated[str, StringConstraints(pattern=r"^INV-\d{1,12}$")]
ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SearchInvoicesArgs(_Strict):
    status: Literal["PENDING", "APPROVED", "REJECTED", "PAID"] | None = None
    mine: bool = False
    query: Annotated[str, StringConstraints(strip_whitespace=True, max_length=100)] | None = None
    limit: int = Field(default=20, ge=1, le=50)


class ReadInvoiceArgs(_Strict):
    invoice_id: InvoiceId


class ApproveInvoiceArgs(_Strict):
    invoice_id: InvoiceId


class CreatePurchaseOrderArgs(_Strict):
    vendor: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)] = "General Vendor"
    description: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] = ""
    amount: Decimal = Field(gt=0, le=Decimal("10000000"), decimal_places=2)
    currency: Literal["USD"] = "USD"


class SearchDocumentsArgs(_Strict):
    query: ShortText
    limit: int = Field(default=10, ge=1, le=25)
