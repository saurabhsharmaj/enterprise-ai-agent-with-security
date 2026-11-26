"""RAG pieces that need no database: chunking, embedding, and permission-filtered retrieval (with fakes)."""
from types import SimpleNamespace

from app.rag import repository as repo
from app.rag import service
from app.rag.chunker import chunk_text
from app.rag.embedder import cosine, get_embedder, tokenize


def test_chunker_sizes_and_overlap():
    text = " ".join(f"Sentence number {i} talks about invoices and approvals." for i in range(60))
    chunks = chunk_text(text, size=300, overlap=60)
    assert len(chunks) > 3 and all(len(c) <= 360 for c in chunks)
    assert chunk_text("") == [] and chunk_text("short.") == ["short."]


def test_chunker_hard_splits_a_giant_sentence():
    assert all(len(c) <= 100 for c in chunk_text("x" * 450, size=100, overlap=10))


def test_embedder_is_deterministic_and_normalised():
    e = get_embedder()
    a, b = e.embed("Invoices above 8000 need human approval"), e.embed("Invoices above 8000 need human approval")
    assert a == b and abs(cosine(a, a) - 1.0) < 1e-9


def test_semantic_ordering():
    e = get_embedder()
    q = e.embed("how are travel meals reimbursed")
    near = cosine(q, e.embed("Meals are reimbursed up to 60 USD per day while travelling."))
    far = cosine(q, e.embed("Privileged access is reviewed quarterly by the security team."))
    assert near > far


def test_tokenizer_drops_stopwords_and_stems():
    assert "the" not in tokenize("the approvals")
    assert tokenize("approved") == tokenize("approving") and tokenize("invoice") == tokenize("invoices")


# ---------------------------------------------------------------------------- permission-filtered retrieval
class FakeOpa:
    def __init__(self, allowed_titles):
        self.allowed_titles, self.seen = allowed_titles, []

    def allowed_ids(self, subject, action, resources):
        self.seen = resources
        return {r["id"] for r in resources if r["id"] in self.allowed_titles}


def _row(doc_id, title, text, cls="INTERNAL", dept="FINANCE", tenant="TENANT_A"):
    return {"document_id": doc_id, "tenant_id": tenant, "title": title, "department": dept, "classification": cls,
            "owner_id": "o", "chunk_index": 0, "content": text, "embedding": get_embedder().embed(text)}


def test_unauthorised_documents_never_reach_ranking(monkeypatch):
    rows = [_row("d1", "Expense Guide", "Meals are reimbursed up to 60 USD per day while travelling."),
            _row("d2", "Compensation", "Executive meals budget reimbursed up to 900 USD per day.", cls="RESTRICTED")]
    monkeypatch.setattr(repo, "candidates", lambda *a, **k: rows)
    opa = FakeOpa({"d1"})
    p = SimpleNamespace(tenant_id="TENANT_A", opa_subject=lambda: {"id": "u"})
    out = service.retrieve(None, opa, p, "how much are meals reimbursed per day?")
    assert [x.document_id for x in out] == ["d1"]
    assert {r["id"] for r in opa.seen} == {"d1", "d2"}          # OPA saw both, and decided


def test_nothing_allowed_means_nothing_returned(monkeypatch):
    monkeypatch.setattr(repo, "candidates", lambda *a, **k: [_row("d1", "A", "meals reimbursed per day")])
    p = SimpleNamespace(tenant_id="TENANT_A", opa_subject=lambda: {})
    assert service.retrieve(None, FakeOpa(set()), p, "meals reimbursed") == []


def test_irrelevant_question_returns_nothing(monkeypatch):
    monkeypatch.setattr(repo, "candidates", lambda *a, **k: [_row("d1", "A", "Meals are reimbursed up to 60 USD.")])
    p = SimpleNamespace(tenant_id="TENANT_A", opa_subject=lambda: {})
    assert service.retrieve(None, FakeOpa({"d1"}), p, "quantum chromodynamics lattice") == []


def test_max_two_chunks_per_document(monkeypatch):
    rows = [dict(_row("d1", "A", f"Invoice approval rule number {i} for managers."), chunk_index=i) for i in range(5)]
    monkeypatch.setattr(repo, "candidates", lambda *a, **k: rows)
    p = SimpleNamespace(tenant_id="TENANT_A", opa_subject=lambda: {})
    assert len(service.retrieve(None, FakeOpa({"d1"}), p, "invoice approval rule managers", top_k=8)) == 2
