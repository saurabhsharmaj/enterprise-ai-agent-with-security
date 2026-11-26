"""Splits a document into overlapping, sentence-aware chunks (about `size` characters)."""
import re

_SENT = re.compile(r"(?<=[.!?])\s+|\n{2,}")


def chunk_text(text: str, size: int = 600, overlap: int = 120) -> list[str]:
    text = (text or "").strip()
    if not text:
        return []
    sentences = [s.strip() for s in _SENT.split(text) if s and s.strip()]
    chunks: list[str] = []
    cur = ""
    for s in sentences:
        while len(s) > size:                      # a single over-long sentence is hard-split
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(s[:size])
            s = s[size - overlap:]
        if cur and len(cur) + 1 + len(s) > size:
            chunks.append(cur)
            tail = cur[-overlap:] if overlap else ""
            cur = (tail.split(" ", 1)[-1] + " " + s).strip() if tail else s
        else:
            cur = f"{cur} {s}".strip()
    if cur:
        chunks.append(cur)
    return chunks
