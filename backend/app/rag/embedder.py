"""Embeddings. The default is a deterministic feature-hashing embedder: no model download, no API key, same
vector on every machine. Swap in a neural embedder by implementing `Embedder` (see README)."""
import hashlib
import math
import re
from typing import Protocol

DIM = 256
_TOKEN = re.compile(r"[a-z0-9]+")
STOPWORDS = frozenset(
    "a an and are as at be by can do does for from how i in is it its of on or our should that the their then "
    "there these this to was we what when where which who why will with you your must may per any".split())


def tokenize(text: str) -> list[str]:
    out = []
    for t in _TOKEN.findall((text or "").lower()):
        if t in STOPWORDS or len(t) < 2:
            continue
        stripped = False
        for suf in ("ing", "ed", "es", "s"):       # tiny stemmer: approved/approving/approve -> approv
            if len(t) > len(suf) + 3 and t.endswith(suf):
                t, stripped = t[: -len(suf)], True
                break
        if not stripped and len(t) > 4 and t.endswith("e"):
            t = t[:-1]
        out.append(t)
    return out


class Embedder(Protocol):
    name: str

    def embed(self, text: str) -> list[float]: ...


class HashingEmbedder:
    name = f"hash-{DIM}-v1"

    def embed(self, text: str) -> list[float]:
        toks = tokenize(text)
        feats = toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]
        vec = [0.0] * DIM
        for f in feats:
            h = hashlib.blake2b(f.encode(), digest_size=8).digest()
            n = int.from_bytes(h, "big")
            vec[n % DIM] += 1.0 if (n >> 63) & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec] if norm else vec


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))        # vectors are L2-normalised


_EMBEDDER = HashingEmbedder()


def get_embedder() -> Embedder:
    return _EMBEDDER
