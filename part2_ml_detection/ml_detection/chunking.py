"""C3 - sliding-window chunker.

Splits normalized text into overlapping windows so one injected sentence in a
long email is not diluted when the classifier looks at it.

Guarantees (asserted in tests/test_chunking.py):
  * every word is covered by at least one window;
  * any run of up to ``overlap_words`` consecutive words lies entirely inside at
    least one window, so an instruction is never cut in half at a boundary;
  * the final window always reaches the end of the text.

The unit is the whitespace word (roughly 1.3 sub-word tokens in English). Unbroken
runs longer than ``max_word_chars`` are split, so a blob with no spaces cannot
become one giant, unscannable "word".

When the text needs more windows than ``max_chunks``, the head and the tail are
kept and the middle is skipped. Tail retention matters: the scenario library's
attacks append text to the end of a document.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Chunk:
    index: int  # position in the full, untruncated window sequence
    start: int  # character offsets into the normalized text
    end: int
    text: str


@dataclass(frozen=True)
class ChunkResult:
    chunks: tuple[Chunk, ...]
    total_chunks: int  # windows the text needs, before any budget cut
    truncated: bool


def _window_starts(n_words: int, window: int, overlap: int) -> list[int]:
    """Word offsets of every window. The last one always covers the final word."""
    stride = window - overlap
    starts = [0]
    nxt = stride
    while nxt + overlap < n_words:
        starts.append(nxt)
        nxt += stride
    return starts


def chunk_text(
    text: str,
    *,
    window_words: int,
    overlap_words: int,
    max_chunks: int,
    max_word_chars: int,
    enabled: bool = True,
) -> ChunkResult:
    """Split ``text`` into overlapping windows (or one whole-text chunk when disabled)."""
    if not text.strip():
        return ChunkResult(chunks=(), total_chunks=0, truncated=False)

    if not enabled:
        stripped = text.strip()
        return ChunkResult(chunks=(Chunk(0, 0, len(text), stripped),), total_chunks=1, truncated=False)

    spans = [m.span() for m in re.finditer(rf"\S{{1,{max_word_chars}}}", text)]
    n_words = len(spans)
    starts = _window_starts(n_words, window_words, overlap_words)
    total = len(starts)

    selected = list(range(total))
    truncated = total > max_chunks
    if truncated:
        head = (max_chunks + 1) // 2
        tail = max_chunks - head
        selected = list(range(head)) + list(range(total - tail, total))

    chunks = []
    for i in selected:
        first = starts[i]
        last = min(first + window_words, n_words) - 1
        begin, end = spans[first][0], spans[last][1]
        chunks.append(Chunk(index=i, start=begin, end=end, text=text[begin:end]))
    return ChunkResult(chunks=tuple(chunks), total_chunks=total, truncated=truncated)