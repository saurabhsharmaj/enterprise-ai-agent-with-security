from app.guardrails import Guardrails
from app.core.config import get_settings
from app.rag.service import best_sentence, retrieve
from app.schemas.tool_args import AskDocumentsArgs
from app.tools.base import Resolved, ToolContext, ToolSpec, collection_resource

WITHHELD = "[passage withheld: it contains instruction-like text (possible prompt injection)]"


def resolve_ask(ctx: ToolContext, args: AskDocumentsArgs) -> Resolved:
    return Resolved(resource=collection_resource(ctx, "document"))


def ask_documents(ctx: ToolContext, args: AskDocumentsArgs, resolved: Resolved) -> dict:
    """RAG: retrieve permission-filtered passages and compose a cited, extractive answer."""
    guard = Guardrails(get_settings().guardrail_mode)
    passages = retrieve(ctx.db, ctx.opa, ctx.principal, args.question, args.top_k)
    out, flagged = [], 0
    for i, p in enumerate(passages, 1):
        flags = guard.scan_untrusted_text(p.text)
        suspicious = bool(flags)
        flagged += suspicious
        withhold = suspicious and guard.mode == "block"
        out.append({"ref": i, "document_id": p.document_id, "title": p.title, "classification": p.classification,
                    "department": p.department, "chunk_index": p.chunk_index, "score": p.score,
                    "suspicious": suspicious, "text": WITHHELD if withhold else p.text})
    usable = [x for x in out if x["text"] != WITHHELD]
    answer = " ".join(f"{best_sentence(x['text'], args.question)} [{x['ref']}]" for x in usable[:2])
    return {"question": args.question, "count": len(out), "flagged_passages": flagged,
            "answer": answer or None, "passages": out}


ASK_DOCUMENTS = ToolSpec("ask_documents", "Answer a question from the knowledge base (RAG), with citations. "
                         "Only documents the caller may read are searched.",
                         "document", "search", AskDocumentsArgs, resolve_ask, ask_documents)
