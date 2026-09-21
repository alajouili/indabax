"""Stand-in detector so Part 3 can build against the real output shape today.

This is NOT a detector and must never be used for a demo or a report. It runs the
*real* pipeline (contract guard, normalizer, chunker, mapper, flags, details) over two
tiny deterministic backends instead of DeBERTa/MiniLM:

  * ``LexicalClassifier`` - 0.99 if a hostile phrase appears, else 0.02;
  * ``HashedEncoder``     - hashed bag-of-word-stems vectors, so cosine ~ stem overlap
                            (a crude proxy: it cannot see synonyms, which real embeddings can).

Because only the two model backends are swapped, every field, flag and threshold
behaves exactly as in production, which lets Part 3 exercise all flag combinations
without downloading a single weight. The same backends power the unit tests.

Usage (from the module root):
    from stub_detector import analyze          # samples/ on sys.path
    signals = analyze({"action_id": "a1", "user_task": "...", ...})
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from typing import Any

import numpy as np

from ml_detection.analyze import analyze as _analyze
from ml_detection.models import Models

HOSTILE_PHRASES = (
    "ignore previous instructions",
    "ignore all previous",
    "ignore previous",
    "note to the ai assistant",
    "note to the assistant",
    "disable monitoring",
    "disable_monitoring",
    "already approved",
    "pre-approved",
    "no further sign-off",
    "do not tell the user",
    "call payment_confirm",
    "call payment_execute",
    "call email_send",
    "call remediation_",
)

_STOPWORDS = frozenset(
    "the a an to of and in on for with is are this that it be as at by from please then also".split()
)
_TOKEN = re.compile(r"[a-z0-9]+")
_SUFFIXES = ("ing", "ize", "ed", "es", "s", "e")
_DIM = 512


def _stem(token: str) -> str:
    """Crude suffix stripping so 'summarize' and 'summarizing' share a stem."""
    for suffix in _SUFFIXES:
        if token.endswith(suffix) and len(token) - len(suffix) >= 4:
            return token[: -len(suffix)]
    return token


class LexicalClassifier:
    def score(self, texts: Sequence[str]) -> list[float]:
        return [0.99 if any(p in t.lower() for p in HOSTILE_PHRASES) else 0.02 for t in texts]


class HashedEncoder:
    def encode(self, texts: Sequence[str]) -> np.ndarray:
        out = np.zeros((len(texts), _DIM), dtype=np.float64)
        for row, text in enumerate(texts):
            for token in _TOKEN.findall(text.lower()):
                if token in _STOPWORDS:
                    continue
                digest = hashlib.blake2b(_stem(token).encode(), digest_size=4).digest()
                out[row, int.from_bytes(digest, "big") % _DIM] += 1.0
            norm = np.linalg.norm(out[row])
            if norm:
                out[row] /= norm
        return out


STUB_MODELS = Models(
    classifier=LexicalClassifier(),
    encoder=HashedEncoder(),
    classifier_version="stub-lexical-classifier@none",
    embedder_version="stub-hashed-encoder@none",
)


def analyze(raw: Any) -> dict[str, Any]:
    """Same signature and output shape as ``ml_detection.analyze.analyze``."""
    return _analyze(raw, models=STUB_MODELS)