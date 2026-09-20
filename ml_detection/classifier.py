"""C4 - injection classifier.

``InjectionClassifier`` wraps the pretrained model (loaded once, CPU, offline,
deterministic). Everything else in this file is pure logic over any object with a
``score(texts) -> list[float]`` method, so it is tested without model weights.

The model card caveats belong in the report: English only, no jailbreak
detection, and it should not be run on system prompts.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .chunking import Chunk

if TYPE_CHECKING:
    from .config import ClassifierModelConfig


class InjectionScorer(Protocol):
    def score(self, texts: Sequence[str]) -> list[float]:
        """Probability in [0, 1] that each text is a prompt injection."""
        ...


class InjectionClassifier:
    """Batched, deterministic wrapper around a Hugging Face sequence classifier."""

    def __init__(self, cfg: ClassifierModelConfig, *, num_threads: int = 1, cache_dir: str | None = None) -> None:
        # Deferred: keeps `import ml_detection` light and lets pure-logic tests run without torch.
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        torch.set_num_threads(num_threads)
        source = {"revision": cfg.revision, "local_files_only": True, "cache_dir": cache_dir}
        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(cfg.id, **source)
        self._model = AutoModelForSequenceClassification.from_pretrained(cfg.id, **source)
        self._model.eval()
        self._max_length = cfg.max_length
        self._batch_size = cfg.batch_size

        wanted = cfg.injection_label.lower()
        matches = [i for i, name in self._model.config.id2label.items() if str(name).lower() == wanted]
        if len(matches) != 1:
            raise ValueError(
                f"model labels {dict(self._model.config.id2label)} do not contain exactly one {cfg.injection_label!r}"
            )
        self._injection_index = int(matches[0])

    def score(self, texts: Sequence[str]) -> list[float]:
        scores: list[float] = []
        for i in range(0, len(texts), self._batch_size):
            batch = list(texts[i : i + self._batch_size])
            encoded = self._tokenizer(
                batch, padding=True, truncation=True, max_length=self._max_length, return_tensors="pt"
            )
            with self._torch.inference_mode():
                logits = self._model(**encoded).logits
            probs = self._torch.softmax(logits.float(), dim=-1)[:, self._injection_index]
            scores.extend(float(p) for p in probs)
        return scores


@dataclass(frozen=True)
class StrongestChunk:
    score: float
    chunk: Chunk | None  # None when there was nothing to scan
    per_chunk: tuple[float, ...]
@dataclass(frozen=True)
class LocalizedEvidence:
    score: float
    text: str | None

def strongest_chunk(chunks: Sequence[Chunk], scorer: InjectionScorer) -> StrongestChunk:
    """Score every chunk; keep the highest probability and remember which chunk produced it."""
    if not chunks:
        return StrongestChunk(score=0.0, chunk=None, per_chunk=())
    scores = scorer.score([c.text for c in chunks])
    if len(scores) != len(chunks):
        raise ValueError(f"scorer returned {len(scores)} scores for {len(chunks)} chunks")
    best = max(range(len(chunks)), key=lambda i: (scores[i], -i))  # ties -> earliest chunk
    return StrongestChunk(score=float(scores[best]), chunk=chunks[best], per_chunk=tuple(float(s) for s in scores))


_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+|\n+")


def split_sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_BREAK.split(text) if s and s.strip()]


def trim(text: str, max_chars: int) -> str:
    text = text.strip()
    return text if len(text) <= max_chars else text[: max_chars - 1].rstrip() + "\u2026"


def localize_evidence(
    chunk_text: str,
    scorer: InjectionScorer,
    *,
    max_sentences: int,
    min_sentence_words: int,
    min_sentence_chars: int,
    context_radius: int,
    max_chars: int,
) -> LocalizedEvidence:
    """Find the strongest meaningful sentence inside a chunk."""

    sentences = [
        s
        for s in split_sentences(chunk_text)
        if len(s) >= min_sentence_chars
        and len(s.split()) >= min_sentence_words
    ]

    if not sentences:
        return LocalizedEvidence(score=0.0, text=None)

    # Keep both beginning and end if there are too many sentences.
    if len(sentences) > max_sentences:
        head = (max_sentences + 1) // 2
        tail = max_sentences - head

        if tail:
            sentences = sentences[:head] + sentences[-tail:]
        else:
            sentences = sentences[:head]

    scores = scorer.score(sentences)

    if len(scores) != len(sentences):
        raise ValueError(
            f"scorer returned {len(scores)} scores for {len(sentences)} sentences"
        )

    best = max(
        range(len(sentences)),
        key=lambda i: (scores[i], -i),
    )

    start = max(0, best - context_radius)
    end = min(len(sentences), best + context_radius + 1)

    span = " ".join(sentences[start:end])

    return LocalizedEvidence(
        score=float(scores[best]),
        text=trim(span, max_chars),
    )