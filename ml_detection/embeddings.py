"""C5 - embedding wrapper.

One model, one ``encode`` call per action for all three strings (task, action,
evidence). Vectors are L2-normalised so cosine similarity is a plain dot product.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol

import numpy as np

if TYPE_CHECKING:
    from .config import EmbedderModelConfig


class TextEncoder(Protocol):
    def encode(self, texts: Sequence[str]) -> np.ndarray:
        """Return an array of shape (len(texts), dim) with L2-normalised rows."""
        ...


class SentenceEncoder:
    """Wrapper around sentence-transformers, loaded once, CPU-only, offline."""

    def __init__(self, cfg: EmbedderModelConfig, *, num_threads: int = 1, cache_dir: str | None = None) -> None:
        import torch
        from sentence_transformers import SentenceTransformer

        torch.set_num_threads(num_threads)
        self._model = SentenceTransformer(
            cfg.id, revision=cfg.revision, local_files_only=True, device="cpu", cache_folder=cache_dir
        )
        self._model.eval()
        self._batch_size = cfg.batch_size

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        vectors = self._model.encode(
            list(texts),
            batch_size=self._batch_size,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return np.asarray(vectors, dtype=np.float64)