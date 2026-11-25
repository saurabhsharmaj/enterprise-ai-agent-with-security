"""FINANCE_AGENT brain: a deterministic, rule-based mock (no LLM, no API key).

It understands requests such as
    "Find my pending invoices."        -> search_invoices {status: PENDING, mine: true}
    "Read invoice INV-1001."           -> read_invoice {invoice_id: INV-1001}
    "Approve invoice INV-1001."        -> approve_invoice {invoice_id: INV-1001}
    "Create a purchase order for 5000" -> create_purchase_order {amount: 5000}
    "Search documents about policy"    -> search_documents {query: policy}

It deliberately proposes whatever was asked, even when the user is not allowed to do it: this makes it
a faithful stand-in for an LLM that can be talked into anything (prompt injection). The security
guarantee comes from the executor + OPA, not from the brain behaving well.
"""
import re
from decimal import Decimal, InvalidOperation

from app.agents.brain import PlannedCall, StepOutcome, ToolDescriptor

_INVOICE_ID = re.compile(r"\bINV-\d{1,12}\b", re.I)
_AMOUNT = re.compile(r"(?<![\w.])(\d{1,3}(?:,\d{3})+|\d+)(\.\d{1,2})?(?![\w])")
_VENDOR = re.compile(r"\bfrom\s+([A-Za-z0-9][A-Za-z0-9 &.\-]{1,60}?)(?=\s+(?:for|worth|of)\b|[.,!?]|$)", re.I)
_STOP = {"find", "search", "show", "list", "get", "me", "the", "a", "an", "for", "about", "on", "of", "all",
         "documents", "document", "my", "any", "please", "and", "with", "containing", "regarding"}


class MockFinanceBrain:
    def plan(self, message: str, tools: list[ToolDescriptor]) -> list[PlannedCall]:
        text = message.strip()
        low = text.lower()
        inv = _INVOICE_ID.search(text)

        if re.search(r"\bapprove\b", low):
            return [PlannedCall("approve_invoice", {"invoice_id": inv.group(0).upper()})] if inv else []

        if re.search(r"\b(create|make|raise|new|submit|place)\b", low) and re.search(r"\bpurchase\s+orders?\b|\bpo\b", low):
            amount = self._amount(text)
            if amount is None:
                return []
            args: dict = {"amount": amount}
            vendor = _VENDOR.search(text)
            if vendor:
                args["vendor"] = vendor.group(1).strip()
            return [PlannedCall("create_purchase_order", args)]

        if re.search(r"\b(documents?|policy|policies|procedures?|runbooks?)\b", low):
            words = [w for w in re.findall(r"[a-z0-9]+", low) if w not in _STOP]
            query = " ".join(words[-2:]) if words else "policy"
            return [PlannedCall("search_documents", {"query": query[:100]})]

        if inv:
            return [PlannedCall("read_invoice", {"invoice_id": inv.group(0).upper()})]

        if re.search(r"\binvoices?\b", low):
            args = {}
            for status in ("pending", "approved", "rejected", "paid"):
                if re.search(rf"\b{status}\b", low):
                    args["status"] = status.upper()
            if re.search(r"\b(my|mine|own)\b", low):
                args["mine"] = True
            return [PlannedCall("search_invoices", args)]
        return []

    @staticmethod
    def _amount(text: str) -> str | None:
        m = _AMOUNT.search(text)
        if not m:
            return None
        try:
            value = Decimal(m.group(1).replace(",", "") + (m.group(2) or ""))
        except InvalidOperation:
            return None
        return format(value, "f")

    # ------------------------------------------------------------------------------------------
    def respond(self, message: str, outcomes: list[StepOutcome]) -> str:
        if not outcomes:
            return ("I can help with invoices and purchase orders. Try: 'Find my pending invoices', "
                    "'Read invoice INV-1001', 'Approve invoice INV-1001', 'Create a purchase order for 5000' "
                    "or 'Search documents about policy'.")
        return "\n".join(self._describe(o) for o in outcomes)

    @staticmethod
    def _describe(o: StepOutcome) -> str:
        if o.status == "pending_approval":
            return f"{o.message} (approval request {o.approval_request_id})"
        if o.status != "success":
            return o.message
        d = o.data or {}
        if o.tool == "search_invoices":
            if not d.get("invoices"):
                return "No invoices matched that search."
            lines = [f"- {i['id']}: {i['vendor']}, {i['amount']} {i['currency']}, {i['status']}" for i in d["invoices"]]
            return f"Found {d['count']} invoice(s):\n" + "\n".join(lines)
        if o.tool == "read_invoice":
            i = d["invoice"]
            return (f"Invoice {i['id']} from {i['vendor']}: {i['amount']} {i['currency']}, status {i['status']}, "
                    f"department {i['department']}, owner {i['owner']}.")
        if o.tool == "approve_invoice":
            return f"Invoice {d['invoice_id']} is now {d['status']}."
        if o.tool == "create_purchase_order":
            po = d["purchase_order"]
            return f"Purchase order {po['po_number']} for {po['amount']} {po['currency']} was created."
        if o.tool == "search_documents":
            if not d.get("documents"):
                return "No documents matched that search."
            return f"Found {d['count']} document(s):\n" + "\n".join(f"- {x['title']} ({x['classification']})" for x in d["documents"])
        return "Done."
