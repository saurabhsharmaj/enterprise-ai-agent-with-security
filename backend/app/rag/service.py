"""RAG service: ingest (chunk + embed + store) and retrieve (authorise -> rank -> cite)."""
import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.rag import repository as repo
from app.rag.chunker import chunk_text
from app.rag.embedder import Embedder, cosine, get_embedder, tokenize

MIN_SCORE = 0.12
MAX_PER_DOC = 2


@dataclass
class Passage:
    document_id: str
    title: str
    classification: str
    department: str
    chunk_index: int
    score: float
    text: str


def ingest_document(db: Session, tenant_id: str, document_id: str, body: str, embedder: Embedder | None = None) -> int:
    emb = embedder or get_embedder()
    chunks = [(i, c, emb.embed(c)) for i, c in enumerate(chunk_text(body))]
    repo.replace_chunks(db, tenant_id, document_id, chunks, emb.name)
    return len(chunks)


def _document_resource(r: dict) -> dict:
    return {"type": "document", "id": str(r["document_id"]), "tenant_id": r["tenant_id"], "department": r["department"],
            "owner_id": str(r["owner_id"]), "classification": r["classification"]}


def retrieve(db: Session, opa, principal, question: str, top_k: int = 4, embedder: Embedder | None = None) -> list[Passage]:
    emb = embedder or get_embedder()
    rows = repo.candidates(db, principal.tenant_id, emb.name)
    # 1) AUTHORISE FIRST: OPA decides per parent document (tenant, department, clearance...). Unauthorised
    #    chunks are dropped before scoring, so they cannot influence ranking, answers, citations or logs.
    docs = {}
    for r in rows:
        docs.setdefault(str(r["document_id"]), _document_resource(r))
    allowed = opa.allowed_ids(principal.opa_subject(), "read", list(docs.values())) if docs else set()
    # 2) rank what remains: cosine similarity + lexical overlap
    qv = emb.embed(question)
    qtok = set(tokenize(question))
    scored = []
    for r in rows:
        if str(r["document_id"]) not in allowed:
            continue
        ctok = set(tokenize(r["content"]))
        lex = len(qtok & ctok) / len(qtok) if qtok else 0.0
        score = 0.6 * max(cosine(qv, list(r["embedding"])), 0.0) + 0.4 * lex
        if score >= MIN_SCORE:
            scored.append((score, r))
    scored.sort(key=lambda x: -x[0])
    out, per_doc = [], {}
    for score, r in scored:
        did = str(r["document_id"])
        if per_doc.get(did, 0) >= MAX_PER_DOC:
            continue
        per_doc[did] = per_doc.get(did, 0) + 1
        out.append(Passage(did, r["title"], r["classification"], r["department"], r["chunk_index"],
                           round(score, 3), r["content"]))
        if len(out) >= top_k:
            break
    return out


_SENT = re.compile(r"(?<=[.!?])\s+")


def best_sentence(passage_text: str, question: str) -> str:
    q = set(tokenize(question))
    sents = [s.strip() for s in _SENT.split(passage_text) if s.strip()] or [passage_text]
    return max(sents, key=lambda s: len(q & set(tokenize(s))))
