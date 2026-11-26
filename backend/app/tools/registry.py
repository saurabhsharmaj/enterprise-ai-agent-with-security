from app.tools.base import ToolSpec
from app.tools.document_tools import SEARCH_DOCUMENTS
from app.tools.invoice_tools import APPROVE_INVOICE, READ_INVOICE, SEARCH_INVOICES
from app.tools.rag_tools import ASK_DOCUMENTS
from app.tools.purchase_order_tools import CREATE_PURCHASE_ORDER

# The single catalogue of executable tools. A name that is not here can never run, whatever an LLM asks for.
REGISTRY: dict[str, ToolSpec] = {
    t.name: t for t in (SEARCH_INVOICES, READ_INVOICE, CREATE_PURCHASE_ORDER, APPROVE_INVOICE, SEARCH_DOCUMENTS,
    ASK_DOCUMENTS)
}
